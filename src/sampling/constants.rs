//! Constants shared by FIPS 204 sampling procedures.

/// Seed length for `RejNTTPoly(ρ)`.
pub(crate) const REJ_NTT_POLY_SEED_BYTES: usize = 34;

/// Seed length for `RejBoundedPoly(ρ)`.
pub(crate) const REJ_BOUNDED_POLY_SEED_BYTES: usize = 66;

/// Seed length for `ExpandA(ρ)`.
pub(crate) const EXPAND_A_SEED_BYTES: usize = 32;

/// Seed length for `ExpandS(ρ')`.
pub(crate) const EXPAND_S_SEED_BYTES: usize = 64;

/// Seed length for `ExpandMask(ρ, μ)`.
pub(crate) const EXPAND_MASK_SEED_BYTES: usize = 64;

macro_rules! define_seed_type {
    ($name:ident, $len:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Builds the seed from its fixed-size byte representation.
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Returns the fixed-size byte representation.
            pub const fn bytes(self) -> [u8; $len] {
                self.0
            }

            /// Borrows the fixed-size byte representation.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(seed: $name) -> Self {
                seed.bytes()
            }
        }
    };
}

define_seed_type!(
    RejNttPolySeed,
    REJ_NTT_POLY_SEED_BYTES,
    "Typed seed for `RejNTTPoly(ρ)`."
);

define_seed_type!(
    RejBoundedPolySeed,
    REJ_BOUNDED_POLY_SEED_BYTES,
    "Typed seed for `RejBoundedPoly(ρ)`."
);

define_seed_type!(
    ExpandASeed,
    EXPAND_A_SEED_BYTES,
    "Typed seed for `ExpandA(ρ)`."
);

define_seed_type!(
    ExpandSSeed,
    EXPAND_S_SEED_BYTES,
    "Typed seed for `ExpandS(ρ')`."
);

define_seed_type!(
    ExpandMaskSeed,
    EXPAND_MASK_SEED_BYTES,
    "Typed seed for `ExpandMask(ρ, μ)`."
);

/// Minimum Table 3 loop limit for `ML-DSA.Sign_internal`.
pub const SIGN_INTERNAL_MIN_LOOP_LIMIT: usize = 814;

/// Minimum Table 3 loop limit for `RejBoundedPoly`.
pub const REJ_BOUNDED_POLY_MIN_LOOP_LIMIT: usize = 481;

/// Minimum Table 3 XOF-byte limit for `RejBoundedPoly`.
pub const REJ_BOUNDED_POLY_MIN_XOF_BYTES: usize = 481;

/// Minimum Table 3 loop limit for `RejNTTPoly`.
pub const REJ_NTT_POLY_MIN_LOOP_LIMIT: usize = 298;

/// Minimum Table 3 XOF-byte limit for `RejNTTPoly`.
pub const REJ_NTT_POLY_MIN_XOF_BYTES: usize = 894;

/// Minimum Table 3 loop limit for `SampleInBall`.
pub const SAMPLE_IN_BALL_MIN_LOOP_LIMIT: usize = 121;

/// Minimum Table 3 XOF-byte limit for `SampleInBall`.
pub const SAMPLE_IN_BALL_MIN_XOF_BYTES: usize = 221;
