use sbproxy_core::hooks::{
    IntentCategory, IntentDetectionHook, PipelineLifecycleHook, PromptClassifierHook,
    QualityScoringHook, StreamSafetyHook,
};

#[test]
fn traits_are_object_safe() {
    fn assert_object_safe<T: ?Sized>() {}
    assert_object_safe::<dyn PromptClassifierHook>();
    assert_object_safe::<dyn IntentDetectionHook>();
    assert_object_safe::<dyn QualityScoringHook>();
    assert_object_safe::<dyn StreamSafetyHook>();
    assert_object_safe::<dyn PipelineLifecycleHook>();
}

#[test]
fn intent_category_general_is_default() {
    let general = IntentCategory::General;
    assert!(matches!(general, IntentCategory::General));
}
