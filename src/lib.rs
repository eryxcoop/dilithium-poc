//! POC de ML-DSA segun FIPS 204 y RFC 9881.
//!
//! El crate todavia esta en fase de scaffold. La planificacion tecnica vive en
//! `roadmap.md` y las notas normativas para colaboradores viven en `AGENTS.md`.

#[cfg(test)]
mod tests {
    #[test]
    fn crate_scaffold_is_ready() {
        assert_eq!(env!("CARGO_PKG_NAME"), "dilithium-poc");
    }
}
