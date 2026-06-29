//! CMS `SignedData` generation.

use crate::error::DilithiumResult;
use crate::ml_dsa::PrivateKey;

use crate::pkix::cms::algorithm::AlgorithmIdentifierDer;
use crate::pkix::cms::attributes::SignedAttributes;
use crate::pkix::cms::der::{DerSet, DerValue};
use crate::pkix::cms::digest::CmsDigestAlgorithm;
use crate::pkix::cms::oid::{ID_DATA, ID_SIGNED_DATA};
use crate::pkix::cms::types::{CmsSignedAttrs, MldsaCmsSignedDataOptions};

/// Encodes and signs a minimal RFC 9882 CMS `ContentInfo(SignedData)`.
///
/// ML-DSA pure mode is always used with an empty context string. If signed
/// attributes are present, the raw content is digested into the
/// `message-digest` attribute and ML-DSA signs the DER `SET OF` encoding of the
/// attributes. If signed attributes are absent, ML-DSA signs `content`
/// directly and emits SHA-512 as the digest algorithm for interoperability.
pub fn encode_mldsa_signed_data(
    private_key: &PrivateKey,
    content: &[u8],
    options: MldsaCmsSignedDataOptions,
) -> DilithiumResult<Vec<u8>> {
    MldsaSignedDataEncoder::new(private_key, content, options).encode()
}

struct MldsaSignedDataEncoder<'a> {
    private_key: &'a PrivateKey,
    content: &'a [u8],
    options: MldsaCmsSignedDataOptions,
}

impl<'a> MldsaSignedDataEncoder<'a> {
    fn new(
        private_key: &'a PrivateKey,
        content: &'a [u8],
        options: MldsaCmsSignedDataOptions,
    ) -> Self {
        Self {
            private_key,
            content,
            options,
        }
    }

    fn encode(&self) -> DilithiumResult<Vec<u8>> {
        let parameter_set = self.private_key.parameter_set();
        let digest_algorithm = self.effective_digest_algorithm()?;
        let signature_algorithm = AlgorithmIdentifierDer::for_signature(parameter_set)?;
        let digest_algorithm_der = AlgorithmIdentifierDer::for_digest(digest_algorithm)?;
        let signed_attrs =
            self.signed_attributes(digest_algorithm, signature_algorithm.as_bytes())?;
        let message_to_sign = signed_attrs
            .as_ref()
            .map(SignedAttributes::to_be_signed_der)
            .unwrap_or_else(|| self.content.to_vec());
        let signature = self.private_key.sign(&message_to_sign, b"")?;
        let signer_info = SignerInfo {
            digest_algorithm: digest_algorithm_der.as_bytes(),
            signature_algorithm: signature_algorithm.as_bytes(),
            signed_attrs: signed_attrs.as_ref(),
            signature: signature.as_bytes(),
        };
        let signed_data = SignedData {
            content: self.content,
            encapsulate_content: self.options.encapsulate_content,
            digest_algorithm: digest_algorithm_der.as_bytes(),
            signer_info,
        };
        ContentInfo::signed_data(signed_data.to_der()?.as_slice()).to_der()
    }

    fn effective_digest_algorithm(&self) -> DilithiumResult<CmsDigestAlgorithm> {
        let parameter_set = self.private_key.parameter_set();
        match self.options.signed_attrs {
            CmsSignedAttrs::Present => {
                self.options
                    .digest_algorithm
                    .require_suitable_for(parameter_set)?;
                Ok(self.options.digest_algorithm)
            }
            CmsSignedAttrs::Absent => Ok(CmsDigestAlgorithm::Sha512),
        }
    }

    fn signed_attributes(
        &self,
        digest_algorithm: CmsDigestAlgorithm,
        signature_algorithm: &[u8],
    ) -> DilithiumResult<Option<SignedAttributes>> {
        match self.options.signed_attrs {
            CmsSignedAttrs::Present => Ok(Some(SignedAttributes::default_for_mldsa(
                self.content,
                digest_algorithm,
                signature_algorithm,
                self.options.include_algorithm_protection,
            )?)),
            CmsSignedAttrs::Absent => Ok(None),
        }
    }
}

struct ContentInfo<'a> {
    signed_data: &'a [u8],
}

impl<'a> ContentInfo<'a> {
    fn signed_data(signed_data: &'a [u8]) -> Self {
        Self { signed_data }
    }

    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        Ok(DerValue::sequence(&[
            DerValue::oid(ID_SIGNED_DATA)?.into_vec(),
            DerValue::context_constructed(0, self.signed_data.to_vec()).into_vec(),
        ])
        .into_vec())
    }
}

struct SignedData<'a> {
    content: &'a [u8],
    encapsulate_content: bool,
    digest_algorithm: &'a [u8],
    signer_info: SignerInfo<'a>,
}

impl SignedData<'_> {
    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        Ok(DerValue::sequence(&[
            DerValue::integer(3).into_vec(),
            DerSet::from_sorted(&[self.digest_algorithm.to_vec()]).to_der(),
            EncapsulatedContentInfo {
                content: self.content,
                encapsulate: self.encapsulate_content,
            }
            .to_der()?,
            DerSet::from_sorted(&[self.signer_info.to_der()?]).to_der(),
        ])
        .into_vec())
    }
}

struct EncapsulatedContentInfo<'a> {
    content: &'a [u8],
    encapsulate: bool,
}

impl EncapsulatedContentInfo<'_> {
    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        let mut fields = vec![DerValue::oid(ID_DATA)?.into_vec()];
        if self.encapsulate {
            fields.push(
                DerValue::context_constructed(0, DerValue::octet_string(self.content).into_vec())
                    .into_vec(),
            );
        }
        Ok(DerValue::sequence(&fields).into_vec())
    }
}

struct SignerInfo<'a> {
    digest_algorithm: &'a [u8],
    signature_algorithm: &'a [u8],
    signed_attrs: Option<&'a SignedAttributes>,
    signature: &'a [u8],
}

impl SignerInfo<'_> {
    fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        let mut fields = vec![
            DerValue::integer(3).into_vec(),
            DerValue::context_primitive(0, &[]).into_vec(),
            self.digest_algorithm.to_vec(),
        ];
        if let Some(signed_attrs) = self.signed_attrs {
            fields.push(signed_attrs.signer_info_field_der()?);
        }
        fields.push(self.signature_algorithm.to_vec());
        fields.push(DerValue::octet_string(self.signature).into_vec());
        Ok(DerValue::sequence(&fields).into_vec())
    }
}
