//! Mistral moderation provider contract.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::{
    generic::normalize_category, ExternalGuardrailRequest, GuardrailCallError, GuardrailVerdict,
    MistralConfig,
};

pub(super) fn mistral_request(
    config: &MistralConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    json!({
        "input": [request.content],
        "model": config.model,
    })
}

pub(super) fn parse_mistral(
    body: &Value,
    config: &MistralConfig,
) -> Result<GuardrailVerdict, GuardrailCallError> {
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .filter(|results| results.len() == 1)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let result = results[0]
        .as_object()
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let categories = result
        .get("categories")
        .and_then(Value::as_object)
        .filter(|categories| !categories.is_empty() && categories.len() <= 32)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let category_scores = result
        .get("category_scores")
        .and_then(Value::as_object)
        .filter(|scores| !scores.is_empty() && scores.len() == categories.len())
        .ok_or(GuardrailCallError::InvalidVerdict)?;

    let mut normalized_categories = Vec::with_capacity(categories.len());
    let mut normalized_scores = BTreeMap::new();
    let mut seen_categories = BTreeSet::new();
    let mut blocked = false;
    for (category_key, category_value) in categories {
        let category =
            normalize_category(category_key).ok_or(GuardrailCallError::InvalidVerdict)?;
        if !seen_categories.insert(category.clone()) {
            return Err(GuardrailCallError::InvalidVerdict);
        }
        let category_flag = category_value
            .as_bool()
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        let score = category_scores
            .get(category_key)
            .and_then(Value::as_f64)
            .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        if normalized_scores.insert(category.clone(), score).is_some() {
            return Err(GuardrailCallError::InvalidVerdict);
        }
        normalized_categories.push(category);
        blocked |= category_flag
            || config
                .score_threshold
                .is_some_and(|threshold| score >= threshold);
    }

    if category_scores
        .keys()
        .any(|key| !categories.contains_key(key))
    {
        return Err(GuardrailCallError::InvalidVerdict);
    }

    Ok(GuardrailVerdict {
        allowed: !blocked,
        reason: blocked.then(|| "mistral blocked content".to_string()),
        categories: normalized_categories,
        scores: normalized_scores,
    })
}
