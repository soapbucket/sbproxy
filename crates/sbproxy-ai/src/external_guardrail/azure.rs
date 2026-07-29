//! Azure AI Content Safety provider contract.

use serde_json::{json, Value};

use super::{
    generic::normalize_category, AzureConfig, ExternalGuardrailRequest, GuardrailCallError,
    GuardrailVerdict,
};

pub(super) fn azure_request(_config: &AzureConfig, request: ExternalGuardrailRequest<'_>) -> Value {
    json!({
        "text": request.content,
        "outputType": "EightSeverityLevels",
    })
}

pub(super) fn parse_azure(
    body: &Value,
    config: &AzureConfig,
) -> Result<GuardrailVerdict, GuardrailCallError> {
    let categories = body
        .get("categoriesAnalysis")
        .and_then(Value::as_array)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let blocklist_matches = body
        .get("blocklistsMatch")
        .and_then(Value::as_array)
        .ok_or(GuardrailCallError::InvalidVerdict)?;

    let mut normalized_categories = Vec::with_capacity(categories.len().min(32));
    let mut blocked = false;
    for category in categories {
        let category_name = category
            .get("category")
            .and_then(Value::as_str)
            .filter(|name| matches!(*name, "Hate" | "SelfHarm" | "Sexual" | "Violence"))
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        let severity = category
            .get("severity")
            .and_then(Value::as_u64)
            .filter(|severity| *severity <= 7)
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        if normalized_categories.len() < 32 {
            if let Some(category) = normalize_category(category_name) {
                normalized_categories.push(category);
            }
        }
        blocked |= severity >= u64::from(config.severity_threshold);
    }

    for item in blocklist_matches {
        for field in ["blocklistName", "blocklistItemId", "blocklistItemText"] {
            item.get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(GuardrailCallError::InvalidVerdict)?;
        }
    }
    blocked |= !blocklist_matches.is_empty();

    Ok(GuardrailVerdict {
        allowed: !blocked,
        reason: blocked.then(|| "azure content safety blocked content".to_string()),
        categories: normalized_categories,
        ..GuardrailVerdict::default()
    })
}
