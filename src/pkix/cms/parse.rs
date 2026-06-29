//! CMS `SignedData` parsing for the minimal RFC 9882 profile.

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::ParameterSet;

use crate::pkix::cms::algorithm::AlgorithmIdentifierDer;
use crate::pkix::cms::der::{DerElement, DerReader, DerSet, DerValue};
use crate::pkix::cms::oid::{ID_DATA, ID_SIGNED_DATA};

#[derive(Clone, Debug)]
pub(crate) struct ParsedSignedData {
    pub(crate) econtent: Option<Vec<u8>>,
    pub(crate) digest_algorithm_der: Vec<u8>,
    pub(crate) signed_attrs: Option<Vec<u8>>,
    pub(crate) signature_parameter_set: ParameterSet,
    pub(crate) signature: Vec<u8>,
}

pub(crate) struct ContentInfoRef<'a> {
    element: DerElement<'a>,
}

impl<'a> ContentInfoRef<'a> {
    pub(crate) fn from_der(der: &'a [u8]) -> DilithiumResult<Self> {
        let element = DerElement::expect_single(der)?;
        if element.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix(
                "CMS ContentInfo must be SEQUENCE",
            ));
        }
        Ok(Self { element })
    }

    pub(crate) fn parse_signed_data(&self) -> DilithiumResult<ParsedSignedData> {
        let mut fields = DerReader::new(self.element.value);
        let content_type = fields.next_oid()?;
        if content_type != ID_SIGNED_DATA {
            return Err(DilithiumError::MalformedPkix(
                "CMS ContentInfo is not signedData",
            ));
        }
        let signed_data = fields.next_element()?;
        fields.finish()?;
        if signed_data.tag != 0xa0 {
            return Err(DilithiumError::MalformedPkix(
                "CMS signedData must be explicitly tagged",
            ));
        }
        let signed_data_inner = DerElement::expect_single(signed_data.value)?;
        SignedDataRef::new(signed_data_inner).parse()
    }
}

struct SignedDataRef<'a> {
    element: DerElement<'a>,
}

impl<'a> SignedDataRef<'a> {
    fn new(element: DerElement<'a>) -> Self {
        Self { element }
    }

    fn parse(&self) -> DilithiumResult<ParsedSignedData> {
        if self.element.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix("SignedData must be SEQUENCE"));
        }
        let mut fields = DerReader::new(self.element.value);
        let _version = fields.next_element()?;
        let _digest_algorithms = fields.next_element()?;
        let econtent = EncapsulatedContentInfoRef::new(fields.next_element()?).parse()?;
        let signer_infos = Self::skip_optional_sets_until_signer_infos(&mut fields)?;
        fields.finish()?;

        let signer_info = DerSet::single_member(signer_infos.value)?;
        let parsed = SignerInfoRef::new(signer_info).parse()?;
        Ok(ParsedSignedData {
            econtent,
            digest_algorithm_der: parsed.digest_algorithm_der,
            signed_attrs: parsed.signed_attrs,
            signature_parameter_set: parsed.signature_parameter_set,
            signature: parsed.signature,
        })
    }

    fn skip_optional_sets_until_signer_infos<'b>(
        fields: &mut DerReader<'b>,
    ) -> DilithiumResult<DerElement<'b>> {
        let mut next = fields.next_element()?;
        while matches!(next.tag, 0xa0 | 0xa1) {
            next = fields.next_element()?;
        }
        if next.tag != 0x31 {
            return Err(DilithiumError::MalformedPkix(
                "SignedData signerInfos must be SET OF",
            ));
        }
        Ok(next)
    }
}

struct EncapsulatedContentInfoRef<'a> {
    element: DerElement<'a>,
}

impl<'a> EncapsulatedContentInfoRef<'a> {
    fn new(element: DerElement<'a>) -> Self {
        Self { element }
    }

    fn parse(&self) -> DilithiumResult<Option<Vec<u8>>> {
        if self.element.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix(
                "encapContentInfo must be SEQUENCE",
            ));
        }
        let mut fields = DerReader::new(self.element.value);
        let content_type = fields.next_oid()?;
        if content_type != ID_DATA {
            return Err(DilithiumError::MalformedPkix(
                "CMS eContentType is not id-data",
            ));
        }
        let content = if fields.is_empty() {
            None
        } else {
            let tagged = fields.next_element()?;
            if tagged.tag != 0xa0 {
                return Err(DilithiumError::MalformedPkix(
                    "CMS eContent must be explicitly tagged",
                ));
            }
            let octets = DerElement::expect_single(tagged.value)?;
            if octets.tag != 0x04 {
                return Err(DilithiumError::MalformedPkix(
                    "CMS eContent must be OCTET STRING",
                ));
            }
            Some(octets.value.to_vec())
        };
        fields.finish()?;
        Ok(content)
    }
}

struct ParsedSignerInfo {
    digest_algorithm_der: Vec<u8>,
    signed_attrs: Option<Vec<u8>>,
    signature_parameter_set: ParameterSet,
    signature: Vec<u8>,
}

struct SignerInfoRef<'a> {
    element: DerElement<'a>,
}

impl<'a> SignerInfoRef<'a> {
    fn new(element: DerElement<'a>) -> Self {
        Self { element }
    }

    fn parse(&self) -> DilithiumResult<ParsedSignerInfo> {
        if self.element.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix("SignerInfo must be SEQUENCE"));
        }
        let mut fields = DerReader::new(self.element.value);
        let _version = fields.next_element()?;
        let _sid = fields.next_element()?;
        let digest_algorithm = fields.next_element()?;
        let mut next = fields.next_element()?;
        let signed_attrs = if next.tag == 0xa0 {
            let set_der = DerValue::set_from_value(next.value).into_vec();
            DerSet::ensure_sorted_value(next.value)?;
            next = fields.next_element()?;
            Some(set_der)
        } else {
            None
        };
        let signature_parameter_set = AlgorithmIdentifierDer::decode_signature(next.der)?;
        let signature = fields.next_octet_string()?.to_vec();
        Self::parse_optional_unsigned_attrs(fields)?;
        Ok(ParsedSignerInfo {
            digest_algorithm_der: digest_algorithm.der.to_vec(),
            signed_attrs,
            signature_parameter_set,
            signature,
        })
    }

    fn parse_optional_unsigned_attrs(mut fields: DerReader<'_>) -> DilithiumResult<()> {
        if !fields.is_empty() {
            let unsigned_attrs = fields.next_element()?;
            if unsigned_attrs.tag != 0xa1 {
                return Err(DilithiumError::MalformedPkix(
                    "unexpected trailing SignerInfo field",
                ));
            }
            fields.finish()?;
        }
        Ok(())
    }
}
