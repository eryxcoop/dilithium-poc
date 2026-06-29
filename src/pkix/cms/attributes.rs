//! CMS signed-attribute construction and parsing.

use der::Decode;
use der::asn1::ObjectIdentifier;

use crate::error::{DilithiumError, DilithiumResult};

use crate::pkix::cms::algorithm::cms_digest_algorithm_der;
use crate::pkix::cms::der::{DerElement, DerReader, DerSequence, DerSet, DerValue};
use crate::pkix::cms::digest::CmsDigestAlgorithm;
use crate::pkix::cms::oid::{
    ID_CMS_ALGORITHM_PROTECTION_ATTR, ID_CONTENT_TYPE_ATTR, ID_DATA, ID_MESSAGE_DIGEST_ATTR,
};

pub(crate) struct SignedAttributes {
    attributes: Vec<Vec<u8>>,
}

impl SignedAttributes {
    pub(crate) fn default_for_mldsa(
        content: &[u8],
        digest_algorithm: CmsDigestAlgorithm,
        signature_algorithm: &[u8],
        include_algorithm_protection: bool,
    ) -> DilithiumResult<Self> {
        let mut attributes = vec![
            CmsAttribute::new(ID_CONTENT_TYPE_ATTR, &[DerValue::oid(ID_DATA)?.into_vec()])
                .to_der()?,
            CmsAttribute::new(
                ID_MESSAGE_DIGEST_ATTR,
                &[DerValue::octet_string(&digest_algorithm.digest(content)).into_vec()],
            )
            .to_der()?,
        ];
        if include_algorithm_protection {
            attributes.push(
                CmsAttribute::new(
                    ID_CMS_ALGORITHM_PROTECTION_ATTR,
                    &[
                        CmsAlgorithmProtection::new(digest_algorithm, signature_algorithm)
                            .to_der()?,
                    ],
                )
                .to_der()?,
            );
        }
        Ok(Self { attributes })
    }

    pub(crate) fn from_attribute_der(attributes: &[Vec<u8>]) -> Self {
        Self {
            attributes: attributes.to_vec(),
        }
    }

    pub(crate) fn from_to_be_signed_der(set_der: &[u8]) -> DilithiumResult<Self> {
        let set = DerElement::expect_single(set_der)?;
        if set.tag != 0x31 {
            return Err(DilithiumError::MalformedPkix(
                "signed attributes to verify must be SET OF",
            ));
        }
        DerSet::ensure_sorted_value(set.value)?;
        let mut reader = DerReader::new(set.value);
        let mut attributes = Vec::new();
        while !reader.is_empty() {
            attributes.push(reader.next_element()?.der.to_vec());
        }
        Ok(Self { attributes })
    }

    pub(crate) fn to_be_signed_der(&self) -> Vec<u8> {
        DerSet::from_unsorted(&self.attributes).to_der()
    }

    pub(crate) fn signer_info_field_der(&self) -> DilithiumResult<Vec<u8>> {
        let set_der = self.to_be_signed_der();
        let set = DerElement::expect_single(&set_der)?;
        Ok(DerValue::context_constructed(0, set.value.to_vec()).into_vec())
    }

    pub(crate) fn parse_required_values(&self) -> DilithiumResult<ParsedSignedAttrs> {
        let mut content_type = None;
        let mut message_digest = None;
        for attr in &self.attributes {
            let (attr_oid, values) = CmsAttribute::parse(attr)?;
            if attr_oid == ID_CONTENT_TYPE_ATTR {
                let value = DerSet::single_member(values)?;
                let oid = ObjectIdentifier::from_der(value.der).map_err(|_| {
                    DilithiumError::MalformedPkix("malformed content-type attribute")
                })?;
                content_type = Some(oid);
            } else if attr_oid == ID_MESSAGE_DIGEST_ATTR {
                let value = DerSet::single_member(values)?;
                if value.tag != 0x04 {
                    return Err(DilithiumError::MalformedPkix(
                        "message-digest attribute must contain OCTET STRING",
                    ));
                }
                message_digest = Some(value.value.to_vec());
            }
        }
        Ok(ParsedSignedAttrs {
            content_type: content_type.ok_or(DilithiumError::MalformedPkix(
                "signedAttrs missing content-type",
            ))?,
            message_digest: message_digest.ok_or(DilithiumError::MalformedPkix(
                "signedAttrs missing message-digest",
            ))?,
        })
    }
}

struct CmsAttribute<'a> {
    oid: ObjectIdentifier,
    values: &'a [Vec<u8>],
}

impl<'a> CmsAttribute<'a> {
    fn new(oid: ObjectIdentifier, values: &'a [Vec<u8>]) -> Self {
        Self { oid, values }
    }

    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        Ok(DerValue::sequence(&[
            DerValue::oid(self.oid)?.into_vec(),
            DerSet::from_unsorted(self.values).to_der(),
        ])
        .into_vec())
    }

    fn parse(attr: &[u8]) -> DilithiumResult<(ObjectIdentifier, &[u8])> {
        let attr = DerElement::expect_single(attr)?;
        if attr.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix(
                "CMS Attribute must be SEQUENCE",
            ));
        }
        let mut fields = DerReader::new(attr.value);
        let oid = fields.next_oid()?;
        let values = fields.next_element()?;
        fields.finish()?;
        if values.tag != 0x31 {
            return Err(DilithiumError::MalformedPkix(
                "CMS Attribute values must be SET OF",
            ));
        }
        DerSet::ensure_sorted_value(values.value)?;
        Ok((oid, values.value))
    }
}

struct CmsAlgorithmProtection<'a> {
    digest_algorithm: CmsDigestAlgorithm,
    signature_algorithm: &'a [u8],
}

impl<'a> CmsAlgorithmProtection<'a> {
    fn new(digest_algorithm: CmsDigestAlgorithm, signature_algorithm: &'a [u8]) -> Self {
        Self {
            digest_algorithm,
            signature_algorithm,
        }
    }

    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        let signature_algorithm_field = DerValue::context_constructed(
            1,
            DerSequence::value_from_der(self.signature_algorithm)?,
        )
        .into_vec();
        Ok(DerValue::sequence(&[
            cms_digest_algorithm_der(self.digest_algorithm)?,
            signature_algorithm_field,
        ])
        .into_vec())
    }
}

/// Encodes CMS signed attributes as the DER `SET OF` value that ML-DSA signs.
///
/// The input elements must be complete DER-encoded `Attribute` values. The
/// function sorts them with DER `SET OF` ordering and wraps them with the
/// universal `SET` tag (`0x31`). `SignerInfo.signedAttrs` stores the same
/// content under an implicit context-specific `[0]` tag, but RFC 9882 signs the
/// universal `SET OF` encoding returned here.
pub fn cms_signed_attrs_to_be_signed_der(attrs: &[Vec<u8>]) -> Vec<u8> {
    SignedAttributes::from_attribute_der(attrs).to_be_signed_der()
}

pub(crate) struct ParsedSignedAttrs {
    pub(crate) content_type: ObjectIdentifier,
    pub(crate) message_digest: Vec<u8>,
}
