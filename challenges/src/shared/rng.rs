//! Small deterministic PRNG helpers for classroom demos.

/// SplitMix64 PRNG with deterministic seeding for repeatable transcripts.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a new generator from a fixed seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next 64-bit word.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Returns a value in `[0, upper)`.
    pub fn range(&mut self, upper: u64) -> u64 {
        self.next_u64() % upper
    }

    /// Returns one pseudo-random bit.
    pub fn bit(&mut self) -> u8 {
        (self.next_u64() >> 63) as u8
    }
}
