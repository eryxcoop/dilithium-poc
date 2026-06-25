#[cfg(feature = "failure-challenges")]
#[test]
fn failure_challenges_feature_can_be_enabled_explicitly() {
    assert!(dilithium_poc_challenges::failure_challenges_enabled());
}
