//! RFC 9881 `OneAsymmetricKey` and ML-DSA private-key CHOICE handling.

use der::asn1::{AnyRef, BitStringRef, ContextSpecificRef, OctetStringRef};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Tag, TagMode,
    TagNumber, Tagged, Writer,
};
use pkcs8::{PrivateKeyInfo, PrivateKeyInfoRef};

use crate::error::{DilithiumError, DilithiumResult};
use crate::ml_dsa::{PrivateKey, PublicKey, keygen_from_seed};
use crate::params::ParameterSet;

use super::algorithm::{algorithm_identifier, validate_absent_parameters};
use super::oid::parameter_set_for_oid;

/// RFC 9881 fixed seed length for ML-DSA private-key import/export.
pub const PRIVATE_KEY_SEED_BYTES: usize = 32;

/// Controls whether redundant RFC 9881 private-key material is checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyCheck {
    /// Regenerate the expanded key from the seed and reject mismatches.
    Enforce,
    /// Parse the DER structure without comparing seed-derived material.
    Skip,
}

/// Private-key material carried by RFC 9881's ML-DSA private-key CHOICE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkixPrivateKey {
    /// Recommended RFC 9881 seed-only format, encoded as `[0] OCTET STRING`.
    Seed([u8; PRIVATE_KEY_SEED_BYTES]),
    /// Expanded raw FIPS 204 private key, encoded as `OCTET STRING`.
    Expanded(PrivateKey),
    /// Both seed and expanded key, encoded as `SEQUENCE`.
    Both {
        /// FIPS 204 key-generation seed `ξ`.
        seed: [u8; PRIVATE_KEY_SEED_BYTES],
        /// Expanded raw FIPS 204 private key.
        expanded_key: PrivateKey,
    },
}

/// Decoded RFC 9881 `OneAsymmetricKey` contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedOneAsymmetricKey {
    parameter_set: ParameterSet,
    private_key: PkixPrivateKey,
    public_key: Option<PublicKey>,
}

impl DecodedOneAsymmetricKey {
    /// Returns the parameter set selected by `privateKeyAlgorithm`.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Returns the decoded ML-DSA private-key CHOICE.
    pub fn private_key(&self) -> &PkixPrivateKey {
        &self.private_key
    }

    /// Returns the optional RFC 5958 public-key field, if present.
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }
}

/// Encodes an RFC 9881 ML-DSA private-key CHOICE as DER.
///
/// The returned bytes are the inner CHOICE value that RFC 9881 places inside
/// `OneAsymmetricKey.privateKey`'s OCTET STRING.
pub fn encode_private_key_choice(private_key: &PkixPrivateKey) -> DilithiumResult<Vec<u8>> {
    match private_key {
        PkixPrivateKey::Seed(seed) => encode_seed_choice(seed),
        PkixPrivateKey::Expanded(private_key) => OctetStringRef::new(private_key.as_bytes())
            .map_err(|_| {
                DilithiumError::MalformedPkix("invalid expanded private key OCTET STRING")
            })?
            .to_der()
            .map_err(|_| DilithiumError::MalformedPkix("failed to encode expanded private key")),
        PkixPrivateKey::Both { seed, expanded_key } => BothPrivateKeyRef {
            seed: OctetStringRef::new(seed)
                .map_err(|_| DilithiumError::MalformedPkix("invalid seed OCTET STRING"))?,
            expanded_key: OctetStringRef::new(expanded_key.as_bytes())
                .map_err(|_| DilithiumError::MalformedPkix("invalid expanded key OCTET STRING"))?,
        }
        .to_der()
        .map_err(|_| DilithiumError::MalformedPkix("failed to encode both private key")),
    }
}

/// Parses an RFC 9881 ML-DSA private-key CHOICE and enforces consistency.
pub fn parse_private_key_choice(
    parameter_set: ParameterSet,
    der: &[u8],
) -> DilithiumResult<PkixPrivateKey> {
    parse_private_key_choice_with_options(parameter_set, der, ConsistencyCheck::Enforce)
}

/// Parses an RFC 9881 ML-DSA private-key CHOICE with configurable consistency.
///
/// The ASN.1 tag selects the variant: context-specific primitive `[0]` for
/// seed, universal `OCTET STRING` for expanded key, and universal `SEQUENCE`
/// for `both`. The parser deliberately does not infer the variant from length.
pub fn parse_private_key_choice_with_options(
    parameter_set: ParameterSet,
    der: &[u8],
    consistency_check: ConsistencyCheck,
) -> DilithiumResult<PkixPrivateKey> {
    let choice = AnyRef::from_der(der)
        .map_err(|_| DilithiumError::MalformedPkix("malformed private-key CHOICE"))?;
    match choice.tag() {
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        } => {
            let seed = fixed_seed(choice.value())?;
            Ok(PkixPrivateKey::Seed(seed))
        }
        Tag::OctetString => {
            let expanded = <&OctetStringRef>::from_der(der)
                .map_err(|_| DilithiumError::MalformedPkix("malformed expanded private key"))?;
            Ok(PkixPrivateKey::Expanded(PrivateKey::from_raw(
                parameter_set,
                expanded.as_bytes().to_vec(),
            )?))
        }
        Tag::Sequence => {
            let both = BothPrivateKeyRef::from_der(der)
                .map_err(|_| DilithiumError::MalformedPkix("malformed both private key"))?;
            let seed = fixed_seed(both.seed.as_bytes())?;
            let expanded_key =
                PrivateKey::from_raw(parameter_set, both.expanded_key.as_bytes().to_vec())?;
            if consistency_check == ConsistencyCheck::Enforce {
                ensure_seed_matches_expanded_key(parameter_set, seed, &expanded_key)?;
            }
            Ok(PkixPrivateKey::Both { seed, expanded_key })
        }
        _ => Err(DilithiumError::MalformedPkix(
            "unknown ML-DSA private-key CHOICE tag",
        )),
    }
}

/// Encodes RFC 9881 `OneAsymmetricKey` DER.
///
/// `private_key` is wrapped in `privateKey` as an OCTET STRING containing the
/// DER-encoded ML-DSA private-key CHOICE. If `public_key` is supplied, RFC 5958
/// version 2 is emitted and the public key field contains the raw FIPS 204
/// public-key bytes.
pub fn encode_one_asymmetric_key(
    parameter_set: ParameterSet,
    private_key: &PkixPrivateKey,
    public_key: Option<&PublicKey>,
) -> DilithiumResult<Vec<u8>> {
    validate_private_key_parameter_set(parameter_set, private_key)?;
    if let Some(public_key) = public_key
        && public_key.parameter_set() != parameter_set
    {
        return Err(DilithiumError::InvalidParameterSet);
    }

    let choice_der = encode_private_key_choice(private_key)?;
    let private_key_octets = OctetStringRef::new(&choice_der)
        .map_err(|_| DilithiumError::MalformedPkix("invalid private key OCTET STRING"))?;
    let public_key_bits = public_key
        .map(|public_key| {
            BitStringRef::from_bytes(public_key.as_bytes())
                .map_err(|_| DilithiumError::MalformedPkix("invalid public key BIT STRING"))
        })
        .transpose()?;
    let mut private_key_info: PrivateKeyInfoRef<'_> =
        PrivateKeyInfo::new(algorithm_identifier(parameter_set)?, private_key_octets);
    private_key_info.public_key = public_key_bits;
    private_key_info
        .to_der()
        .map_err(|_| DilithiumError::MalformedPkix("failed to encode OneAsymmetricKey"))
}

/// Parses RFC 9881 `OneAsymmetricKey` DER and enforces consistency checks.
pub fn parse_one_asymmetric_key(der: &[u8]) -> DilithiumResult<DecodedOneAsymmetricKey> {
    parse_one_asymmetric_key_with_options(der, ConsistencyCheck::Enforce)
}

/// Parses RFC 9881 `OneAsymmetricKey` DER with configurable consistency.
///
/// `AlgorithmIdentifier.parameters` must be absent. If a `both` private key is
/// present and consistency checking is enabled, the expanded key must equal the
/// FIPS 204 key generated from the seed.
pub fn parse_one_asymmetric_key_with_options(
    der: &[u8],
    consistency_check: ConsistencyCheck,
) -> DilithiumResult<DecodedOneAsymmetricKey> {
    let private_key_info = PrivateKeyInfoRef::from_der(der)
        .map_err(|_| DilithiumError::MalformedPkix("malformed OneAsymmetricKey DER"))?;
    validate_absent_parameters(&private_key_info.algorithm)?;
    let parameter_set = parameter_set_for_oid(private_key_info.algorithm.oid)?;
    let private_key = parse_private_key_choice_with_options(
        parameter_set,
        private_key_info.private_key.as_bytes(),
        consistency_check,
    )?;
    let public_key = private_key_info
        .public_key
        .map(|bits| {
            let bytes = bits.as_bytes().ok_or(DilithiumError::MalformedPkix(
                "public key BIT STRING must be octet-aligned",
            ))?;
            PublicKey::from_raw(parameter_set, bytes.to_vec())
        })
        .transpose()?;
    if consistency_check == ConsistencyCheck::Enforce {
        ensure_public_key_consistency(parameter_set, &private_key, public_key.as_ref())?;
    }
    Ok(DecodedOneAsymmetricKey {
        parameter_set,
        private_key,
        public_key,
    })
}

fn encode_seed_choice(seed: &[u8; PRIVATE_KEY_SEED_BYTES]) -> DilithiumResult<Vec<u8>> {
    let octets = OctetStringRef::new(seed)
        .map_err(|_| DilithiumError::MalformedPkix("invalid seed OCTET STRING"))?;
    ContextSpecificRef {
        tag_number: TagNumber(0),
        tag_mode: TagMode::Implicit,
        value: &octets,
    }
    .to_der()
    .map_err(|_| DilithiumError::MalformedPkix("failed to encode seed private key"))
}

fn fixed_seed(seed: &[u8]) -> DilithiumResult<[u8; PRIVATE_KEY_SEED_BYTES]> {
    if seed.len() != PRIVATE_KEY_SEED_BYTES {
        return Err(DilithiumError::InvalidLength {
            expected: PRIVATE_KEY_SEED_BYTES,
            actual: seed.len(),
            item: "PKIX private key seed",
        });
    }
    let mut fixed = [0u8; PRIVATE_KEY_SEED_BYTES];
    fixed.copy_from_slice(seed);
    Ok(fixed)
}

fn validate_private_key_parameter_set(
    parameter_set: ParameterSet,
    private_key: &PkixPrivateKey,
) -> DilithiumResult<()> {
    match private_key {
        PkixPrivateKey::Seed(_) => Ok(()),
        PkixPrivateKey::Expanded(private_key) => {
            if private_key.parameter_set() == parameter_set {
                Ok(())
            } else {
                Err(DilithiumError::InvalidParameterSet)
            }
        }
        PkixPrivateKey::Both { expanded_key, .. } => {
            if expanded_key.parameter_set() == parameter_set {
                Ok(())
            } else {
                Err(DilithiumError::InvalidParameterSet)
            }
        }
    }
}

fn ensure_seed_matches_expanded_key(
    parameter_set: ParameterSet,
    seed: [u8; PRIVATE_KEY_SEED_BYTES],
    expanded_key: &PrivateKey,
) -> DilithiumResult<()> {
    let generated = keygen_from_seed(parameter_set, seed)?;
    if generated.private_key().as_bytes() == expanded_key.as_bytes() {
        Ok(())
    } else {
        Err(DilithiumError::InconsistentPrivateKey(
            "seed does not regenerate expanded private key",
        ))
    }
}

fn ensure_public_key_consistency(
    parameter_set: ParameterSet,
    private_key: &PkixPrivateKey,
    public_key: Option<&PublicKey>,
) -> DilithiumResult<()> {
    let Some(public_key) = public_key else {
        return Ok(());
    };
    let seed = match private_key {
        PkixPrivateKey::Seed(seed) | PkixPrivateKey::Both { seed, .. } => *seed,
        PkixPrivateKey::Expanded(_) => return Ok(()),
    };
    let generated = keygen_from_seed(parameter_set, seed)?;
    if generated.public_key().as_bytes() == public_key.as_bytes() {
        Ok(())
    } else {
        Err(DilithiumError::InconsistentPrivateKey(
            "seed does not regenerate public key",
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BothPrivateKeyRef<'a> {
    seed: &'a OctetStringRef,
    expanded_key: &'a OctetStringRef,
}

impl<'a> DecodeValue<'a> for BothPrivateKeyRef<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            Ok(Self {
                seed: reader.decode()?,
                expanded_key: reader.decode()?,
            })
        })
    }
}

impl EncodeValue for BothPrivateKeyRef<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.seed.encoded_len()? + self.expanded_key.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.seed.encode(writer)?;
        self.expanded_key.encode(writer)?;
        Ok(())
    }
}

impl<'a> Sequence<'a> for BothPrivateKeyRef<'a> {}
