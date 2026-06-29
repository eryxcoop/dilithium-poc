//! CMS `SignedData` verification.

use crate::error::{DilithiumError, DilithiumResult};
use crate::ml_dsa::{PublicKey, Signature};

use crate::pkix::cms::algorithm::AlgorithmIdentifierDer;
use crate::pkix::cms::attributes::SignedAttributes;
use crate::pkix::cms::oid::ID_DATA;
use crate::pkix::cms::parse::ContentInfoRef;

/// Verifies a minimal RFC 9882 ML-DSA CMS `ContentInfo(SignedData)`.
///
/// If the CMS object is detached, `detached_content` supplies the external
/// content octets. If content is encapsulated, the embedded `eContent` is used
/// and `detached_content` is ignored.
pub fn verify_mldsa_signed_data(
    public_key: &PublicKey,
    der: &[u8],
    detached_content: Option<&[u8]>,
) -> DilithiumResult<bool> {
    MldsaSignedDataVerifier::new(public_key, der, detached_content).verify()
}

struct MldsaSignedDataVerifier<'a> {
    public_key: &'a PublicKey,
    der: &'a [u8],
    detached_content: Option<&'a [u8]>,
}

impl<'a> MldsaSignedDataVerifier<'a> {
    fn new(public_key: &'a PublicKey, der: &'a [u8], detached_content: Option<&'a [u8]>) -> Self {
        Self {
            public_key,
            der,
            detached_content,
        }
    }

    fn verify(&self) -> DilithiumResult<bool> {
        let parsed = ContentInfoRef::from_der(self.der)?.parse_signed_data()?;
        let content = self.resolve_content(parsed.econtent)?;
        if parsed.signature_parameter_set != self.public_key.parameter_set() {
            return Ok(false);
        }
        let signature = Signature::from_raw(parsed.signature_parameter_set, parsed.signature)?;
        let message = if let Some(signed_attrs) = parsed.signed_attrs {
            match self.verify_signed_attrs(&signed_attrs, &parsed.digest_algorithm_der, &content)? {
                Some(message) => message,
                None => return Ok(false),
            }
        } else {
            content
        };

        Ok(self.public_key.verify(&message, &signature, b""))
    }

    fn resolve_content(&self, econtent: Option<Vec<u8>>) -> DilithiumResult<Vec<u8>> {
        match econtent {
            Some(content) => Ok(content),
            None => self
                .detached_content
                .map(<[u8]>::to_vec)
                .ok_or(DilithiumError::MalformedPkix("CMS content is detached")),
        }
    }

    fn verify_signed_attrs(
        &self,
        signed_attrs: &[u8],
        digest_algorithm_der: &[u8],
        content: &[u8],
    ) -> DilithiumResult<Option<Vec<u8>>> {
        let digest_algorithm = AlgorithmIdentifierDer::decode_digest(digest_algorithm_der)?;
        digest_algorithm.require_suitable_for(self.public_key.parameter_set())?;
        let attributes =
            SignedAttributes::from_to_be_signed_der(signed_attrs)?.parse_required_values()?;
        if attributes.content_type != ID_DATA {
            return Ok(None);
        }
        if attributes.message_digest != digest_algorithm.digest(content) {
            return Ok(None);
        }
        Ok(Some(signed_attrs.to_vec()))
    }
}
