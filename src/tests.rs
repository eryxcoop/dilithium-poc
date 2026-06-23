use super::*;

#[test]
fn crate_scaffold_is_ready() {
    assert_eq!(env!("CARGO_PKG_NAME"), "dilithium-poc");
}

#[test]
fn fips_parameter_sets_are_exposed() {
    assert_eq!(ML_DSA_44.sizes.public_key_bytes, 1312);
    assert_eq!(ML_DSA_65.sizes.private_key_bytes, 4032);
    assert_eq!(ML_DSA_87.sizes.signature_bytes, 4627);
}

#[test]
fn core_params_are_grouped() {
    assert_eq!(ML_DSA_44.core.k, 4);
    assert_eq!(ML_DSA_65.core.gamma1, 1 << 19);
    assert_eq!(ML_DSA_87.core.omega, 75);
}
