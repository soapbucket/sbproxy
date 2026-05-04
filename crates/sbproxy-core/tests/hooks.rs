use sbproxy_core::hooks::{
    EnterpriseStartupHook, IntentCategory, IntentDetectionHook, PromptClassifierHook,
    QualityScoringHook, SemanticLookupHook, StreamCacheRecorderHook, StreamSafetyHook,
};

#[test]
fn traits_are_object_safe() {
    fn assert_object_safe<T: ?Sized>() {}
    assert_object_safe::<dyn PromptClassifierHook>();
    assert_object_safe::<dyn IntentDetectionHook>();
    assert_object_safe::<dyn QualityScoringHook>();
    assert_object_safe::<dyn SemanticLookupHook>();
    assert_object_safe::<dyn StreamSafetyHook>();
    assert_object_safe::<dyn StreamCacheRecorderHook>();
    assert_object_safe::<dyn EnterpriseStartupHook>();
}

#[test]
fn intent_category_general_is_default() {
    let general = IntentCategory::General;
    assert!(matches!(general, IntentCategory::General));
}
