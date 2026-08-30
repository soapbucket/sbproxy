use std::ops::Range;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tokenizers::models::ModelWrapper;
use tokenizers::normalizers::NormalizerWrapper;
use tokenizers::pre_tokenizers::metaspace::PrependScheme;
use tokenizers::pre_tokenizers::PreTokenizerWrapper;
use tokenizers::{Encoding, PostProcessor, Tokenizer};
use tract_onnx::pb::{tensor_proto, tensor_shape_proto, type_proto, ModelProto, ValueInfoProto};
use tract_onnx::prelude::*;

use crate::{check_size_budget, LoadOptions, RunnableOnnxModel};

/// Requested output size for token-classifier compression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenCompressionTarget {
    /// Retain this fraction of the model-tokenized input.
    RetainRatio(f64),
    /// Retain no more than this many model tokens.
    TargetTokens(usize),
}

/// Per-call work limits applied before token-model inference begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCompressionLimits {
    /// Maximum tokenizer tokens accepted in the source text.
    pub max_input_tokens: usize,
    /// Maximum model windows evaluated for one source text.
    pub max_windows: usize,
}

impl Default for TokenCompressionLimits {
    fn default() -> Self {
        Self {
            max_input_tokens: 131_072,
            max_windows: 256,
        }
    }
}

/// A request exceeded one of the configured token-compression work limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenCompressionLimitError {
    /// The tokenizer produced more source tokens than one request may process.
    #[error("compression input token limit exceeded: {actual} > {limit}")]
    InputTokens {
        /// Number of source tokens produced by the tokenizer.
        actual: usize,
        /// Configured maximum source-token count.
        limit: usize,
    },
    /// Windowing produced more model invocations than one request may run.
    #[error("compression inference window limit exceeded: {actual} > {limit}")]
    Windows {
        /// Number of model-inference windows required by the source.
        actual: usize,
        /// Configured maximum model-inference window count.
        limit: usize,
    },
}

/// Extractive token-compression result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCompressionOutput {
    /// Text reconstructed exclusively from source spans.
    pub text: String,
    /// Source token count according to the compression tokenizer.
    pub original_tokens: usize,
    /// Retained token count according to the compression tokenizer.
    pub compressed_tokens: usize,
}

/// Pure-Rust ONNX token classifier used for extractive text compression.
///
/// The model must emit `f32` logits shaped `[1, sequence, 2]`, where class
/// index 1 is the probability that the source token should be retained.
pub struct OnnxTokenClassifier {
    model: RunnableOnnxModel,
    tokenizer: Tokenizer,
    tokenizer_contract: BoundarySeparableTokenizer,
    max_model_tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundarySeparableTokenizer {
    BertWordPiece,
    XlmRobertaUnigram,
}

#[derive(Debug, Clone, Copy)]
struct TokenObservation {
    start: usize,
    end: usize,
    word_id: Option<u32>,
    keep_probability: f32,
}

impl TokenObservation {
    #[cfg(test)]
    fn boundary(start: usize, end: usize, word_id: Option<u32>) -> Self {
        Self {
            start,
            end,
            word_id,
            keep_probability: 0.5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WordScore {
    start: usize,
    end: usize,
    score: f32,
    token_count: usize,
    ordinal: usize,
}

const MAX_BUDGET_CORRECTION_ATTEMPTS: usize = 24;

fn aggregate_word_scores(
    source: &str,
    observations: &[TokenObservation],
    ordinal_base: usize,
) -> Result<Vec<WordScore>> {
    let mut words: Vec<WordScore> = Vec::new();
    let mut previous_word_id = None;

    for observation in observations {
        validate_observation(source, observation)?;
        let same_word = observation.word_id.is_some()
            && observation.word_id == previous_word_id
            && words.last().is_some();
        if same_word {
            let word = words.last_mut().expect("checked above");
            let total = word.score * word.token_count as f32 + observation.keep_probability;
            word.token_count += 1;
            word.score = total / word.token_count as f32;
            word.start = word.start.min(observation.start);
            word.end = word.end.max(observation.end);
        } else {
            if let Some(previous) = words.last() {
                if observation.start < previous.end {
                    return Err(anyhow!("token offsets overlap across words"));
                }
            }
            words.push(WordScore {
                start: observation.start,
                end: observation.end,
                score: observation.keep_probability,
                token_count: 1,
                ordinal: ordinal_base + words.len(),
            });
        }
        previous_word_id = observation.word_id;
    }

    Ok(words)
}

fn validate_observation(source: &str, observation: &TokenObservation) -> Result<()> {
    if observation.start >= observation.end
        || observation.end > source.len()
        || !source.is_char_boundary(observation.start)
        || !source.is_char_boundary(observation.end)
    {
        return Err(anyhow!(
            "token offsets {}..{} are invalid for a {}-byte source",
            observation.start,
            observation.end,
            source.len()
        ));
    }
    if !observation.keep_probability.is_finite()
        || !(0.0..=1.0).contains(&observation.keep_probability)
    {
        return Err(anyhow!("token keep probability is not in [0, 1]"));
    }
    Ok(())
}

fn partition_windows(
    source: &str,
    observations: &[TokenObservation],
    max_model_tokens: usize,
) -> Result<Vec<Range<usize>>> {
    let content_limit = max_model_tokens
        .checked_sub(2)
        .filter(|limit| *limit > 0)
        .ok_or_else(|| anyhow!("model window must allow two special tokens and content"))?;
    for observation in observations {
        validate_observation(source, observation)?;
    }
    for pair in observations.windows(2) {
        let same_word = pair[0].word_id.is_some() && pair[0].word_id == pair[1].word_id;
        if !same_word && (pair[0].start > pair[1].start || pair[0].end > pair[1].start) {
            return Err(anyhow!("token offsets are not ordered and non-overlapping"));
        }
    }

    let mut windows = Vec::new();
    let mut start = 0;
    while start < observations.len() {
        let hard_end = (start + content_limit).min(observations.len());
        let mut end = hard_end;
        while end > start && splits_word(observations, end) {
            end -= 1;
        }
        if end == start {
            return Err(anyhow!("word exceeds model window"));
        }

        let minimum_boundary = start + (end - start).div_ceil(2);
        if let Some(boundary) = ((minimum_boundary + 1)..=end).rev().find(|candidate| {
            !splits_word(observations, *candidate)
                && is_punctuation_boundary(source, observations, *candidate)
        }) {
            end = boundary;
        }

        windows.push(start..end);
        start = end;
    }
    Ok(windows)
}

fn splits_word(observations: &[TokenObservation], end: usize) -> bool {
    end < observations.len()
        && observations[end - 1].word_id.is_some()
        && observations[end - 1].word_id == observations[end].word_id
}

fn is_punctuation_boundary(source: &str, observations: &[TokenObservation], end: usize) -> bool {
    let observation = observations[end - 1];
    let token_has_boundary = source[observation.start..observation.end]
        .chars()
        .next_back()
        .is_some_and(|character| matches!(character, '.' | '!' | '?' | ';'));
    let next_start = observations
        .get(end)
        .map_or(source.len(), |next| next.start);
    let gap_has_newline = source[observation.end..next_start].contains('\n');
    token_has_boundary || gap_has_newline
}

#[cfg(test)]
fn select_and_reconstruct(
    source: &str,
    words: &[WordScore],
    original_tokens: usize,
    target: TokenCompressionTarget,
) -> Result<TokenCompressionOutput> {
    validate_scored_words(source, words, original_tokens)?;
    let budget = target_budget(original_tokens, target)?;
    if budget >= original_tokens {
        return Ok(TokenCompressionOutput {
            text: source.to_string(),
            original_tokens,
            compressed_tokens: original_tokens,
        });
    }

    let selected = rank_and_pack_words(words, budget);
    reconstruct_ranked_prefix(source, &selected, selected.len(), original_tokens)
}

fn validate_scored_words(source: &str, words: &[WordScore], original_tokens: usize) -> Result<()> {
    if source.is_empty() || words.is_empty() || original_tokens == 0 {
        return Err(anyhow!("compression input contains no tokens"));
    }
    for word in words {
        if word.start >= word.end
            || word.end > source.len()
            || !source.is_char_boundary(word.start)
            || !source.is_char_boundary(word.end)
            || word.token_count == 0
            || !word.score.is_finite()
        {
            return Err(anyhow!("invalid scored word"));
        }
    }
    Ok(())
}

fn rank_and_pack_words(words: &[WordScore], budget: usize) -> Vec<WordScore> {
    let mut ranked = (0..words.len()).collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        words[*right]
            .score
            .total_cmp(&words[*left].score)
            .then_with(|| words[*left].ordinal.cmp(&words[*right].ordinal))
            .then_with(|| words[*left].start.cmp(&words[*right].start))
    });

    let mut retained_tokens = 0;
    let mut selected = Vec::new();
    for index in ranked {
        let word = words[index];
        if retained_tokens + word.token_count <= budget {
            retained_tokens += word.token_count;
            selected.push(word);
        }
    }
    selected
}

fn reconstruct_ranked_prefix(
    source: &str,
    ranked_selection: &[WordScore],
    prefix_len: usize,
    original_tokens: usize,
) -> Result<TokenCompressionOutput> {
    if prefix_len == 0 {
        return Err(anyhow!("target is too small to retain a complete word"));
    }
    let retained_tokens = ranked_selection[..prefix_len]
        .iter()
        .map(|word| word.token_count)
        .sum();
    let mut selected = ranked_selection[..prefix_len].to_vec();
    selected.sort_by_key(|word| (word.start, word.ordinal));
    for pair in selected.windows(2) {
        if pair[0].end > pair[1].start {
            return Err(anyhow!("selected source spans overlap"));
        }
    }

    let text = reconstruct_source_spans(source, &selected);
    if text.is_empty() {
        return Err(anyhow!("compression produced empty text"));
    }
    Ok(TokenCompressionOutput {
        text,
        original_tokens,
        compressed_tokens: retained_tokens,
    })
}

fn select_with_bounded_token_correction<F>(
    source: &str,
    words: &[WordScore],
    original_tokens: usize,
    target: TokenCompressionTarget,
    _tokenizer_contract: BoundarySeparableTokenizer,
    mut count_tokens: F,
) -> Result<(TokenCompressionOutput, usize)>
where
    F: FnMut(&str) -> Result<usize>,
{
    validate_scored_words(source, words, original_tokens)?;
    let budget = target_budget(original_tokens, target)?;
    if budget >= original_tokens {
        return Ok((
            TokenCompressionOutput {
                text: source.to_string(),
                original_tokens,
                compressed_tokens: original_tokens,
            },
            0,
        ));
    }

    // Rank and greedily pack once. Corrections only drop a suffix of this
    // ranked selection, preserving the original score ordering without
    // reranking all words on every tokenizer measurement.
    let selected = rank_and_pack_words(words, budget);
    if selected.is_empty() {
        return Err(anyhow!("target is too small to retain a complete word"));
    }

    let mut attempts = 1;
    let mut candidate =
        reconstruct_ranked_prefix(source, &selected, selected.len(), original_tokens)?;
    candidate.compressed_tokens = count_tokens(&candidate.text)?;
    if candidate.compressed_tokens <= budget {
        return Ok((candidate, attempts));
    }

    // A reconstructed one-word prefix may include terminal punctuation, so
    // first retain a measured fallback containing only the highest-ranked
    // complete source word.
    let top_word = selected[0];
    let mut fallback = TokenCompressionOutput {
        text: source[top_word.start..top_word.end].to_string(),
        original_tokens,
        compressed_tokens: top_word.token_count,
    };
    attempts += 1;
    fallback.compressed_tokens = count_tokens(&fallback.text)?;
    if fallback.compressed_tokens > budget {
        return Err(anyhow!(
            "highest-ranked complete word exceeds the compression target"
        ));
    }

    if selected.len() == 1 {
        return Ok((fallback, attempts));
    }

    // The validated tokenizer contract makes complete reconstructed word
    // prefixes boundary-separable, and therefore their token counts
    // nondecreasing. Verify the decorated one-word low before using that
    // invariant as the ordering predicate for binary search.
    let mut low_candidate = reconstruct_ranked_prefix(source, &selected, 1, original_tokens)?;
    attempts += 1;
    low_candidate.compressed_tokens = count_tokens(&low_candidate.text)?;
    if low_candidate.compressed_tokens > budget {
        return Ok((fallback, attempts));
    }

    let mut best = low_candidate;
    let mut low = 2;
    let mut high = selected.len() - 1;
    while low <= high && attempts < MAX_BUDGET_CORRECTION_ATTEMPTS {
        let prefix_len = low + (high - low) / 2;
        let mut candidate =
            reconstruct_ranked_prefix(source, &selected, prefix_len, original_tokens)?;
        attempts += 1;
        candidate.compressed_tokens = count_tokens(&candidate.text)?;
        if candidate.compressed_tokens <= budget {
            best = candidate;
            low = prefix_len + 1;
        } else {
            high = prefix_len - 1;
        }
    }

    Ok((best, attempts))
}

fn target_budget(original_tokens: usize, target: TokenCompressionTarget) -> Result<usize> {
    match target {
        TokenCompressionTarget::RetainRatio(ratio)
            if ratio.is_finite() && ratio > 0.0 && ratio <= 1.0 =>
        {
            Ok(((original_tokens as f64 * ratio).ceil() as usize).min(original_tokens))
        }
        TokenCompressionTarget::RetainRatio(_) => {
            Err(anyhow!("retain ratio must be finite and in (0, 1]"))
        }
        TokenCompressionTarget::TargetTokens(tokens) if tokens > 0 => {
            Ok(tokens.min(original_tokens))
        }
        TokenCompressionTarget::TargetTokens(_) => {
            Err(anyhow!("target token count must be greater than zero"))
        }
    }
}

fn validate_compression_work(
    input_tokens: usize,
    windows: usize,
    limits: TokenCompressionLimits,
) -> Result<()> {
    if limits.max_input_tokens == 0 || limits.max_windows == 0 {
        return Err(anyhow!(
            "token compression work limits must be greater than zero"
        ));
    }
    if input_tokens > limits.max_input_tokens {
        return Err(TokenCompressionLimitError::InputTokens {
            actual: input_tokens,
            limit: limits.max_input_tokens,
        }
        .into());
    }
    if windows > limits.max_windows {
        return Err(TokenCompressionLimitError::Windows {
            actual: windows,
            limit: limits.max_windows,
        }
        .into());
    }
    Ok(())
}

fn reconstruct_source_spans(source: &str, selected: &[WordScore]) -> String {
    let mut output = String::new();
    let mut previous_end = None;
    for word in selected {
        if let Some(end) = previous_end {
            output.push_str(non_alphanumeric_prefix(&source[end..word.start]));
        }
        output.push_str(&source[word.start..word.end]);
        previous_end = Some(word.end);
    }
    if let Some(end) = previous_end {
        let suffix = &source[end..];
        if !suffix.chars().any(char::is_alphanumeric) {
            output.push_str(suffix);
        }
    }
    output
}

fn non_alphanumeric_prefix(value: &str) -> &str {
    let end = value
        .char_indices()
        .find_map(|(offset, character)| character.is_alphanumeric().then_some(offset))
        .unwrap_or(value.len());
    &value[..end]
}

fn keep_probabilities_from_logits(
    logits: &[f32],
    shape: &[usize],
    sequence_len: usize,
) -> Result<Vec<f32>> {
    let expected = [1, sequence_len, 2];
    if shape != expected || logits.len() != sequence_len.saturating_mul(2) {
        return Err(anyhow!(
            "expected [1, {sequence_len}, 2] token logits, got shape {shape:?}"
        ));
    }
    logits
        // `as_chunks::<2>()` rather than `chunks_exact(2)`: the chunk
        // size is a constant, so the iterator yields `&[f32; 2]` and the
        // two indexes below are checked by the type instead of at run
        // time. The length check above rejects anything that is not
        // exactly `sequence_len * 2` values, so the remainder half this
        // discards is always empty.
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if !pair[0].is_finite() || !pair[1].is_finite() {
                return Err(anyhow!("token logits contain a non-finite value"));
            }
            let maximum = pair[0].max(pair[1]);
            let discard = (pair[0] - maximum).exp();
            let keep = (pair[1] - maximum).exp();
            let denominator = discard + keep;
            if !denominator.is_finite() || denominator <= 0.0 {
                return Err(anyhow!("token softmax denominator is invalid"));
            }
            Ok(keep / denominator)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenModelInput {
    InputIds,
    AttentionMask,
    TokenTypeIds,
}

fn token_model_input(name: &str) -> Option<TokenModelInput> {
    match name.to_ascii_lowercase().as_str() {
        "input_ids" | "ids" => Some(TokenModelInput::InputIds),
        "attention_mask" => Some(TokenModelInput::AttentionMask),
        "token_type_ids" => Some(TokenModelInput::TokenTypeIds),
        _ => None,
    }
}

fn validate_token_model_signature(model: &ModelProto) -> Result<()> {
    let graph = model
        .graph
        .as_ref()
        .ok_or_else(|| anyhow!("ONNX token model is missing its inference graph"))?;
    let mut has_input_ids = false;
    let mut has_attention_mask = false;
    let mut has_token_type_ids = false;
    for input in &graph.input {
        let role = token_model_input(&input.name).ok_or_else(|| {
            anyhow!(
                "unsupported token model input {:?}; expected input_ids, attention_mask, or token_type_ids",
                input.name
            )
        })?;
        validate_input_tensor(input)?;
        let seen = match role {
            TokenModelInput::InputIds => &mut has_input_ids,
            TokenModelInput::AttentionMask => &mut has_attention_mask,
            TokenModelInput::TokenTypeIds => &mut has_token_type_ids,
        };
        if *seen {
            return Err(anyhow!("duplicate token model input {:?}", input.name));
        }
        *seen = true;
    }
    if !has_input_ids || !has_attention_mask {
        return Err(anyhow!(
            "token model requires input_ids and attention_mask inputs"
        ));
    }
    if graph.output.len() != 1 {
        return Err(anyhow!(
            "token model must declare exactly one logits output, found {}",
            graph.output.len()
        ));
    }
    validate_output_tensor(&graph.output[0])
}

fn tensor_type<'a>(value: &'a ValueInfoProto, description: &str) -> Result<&'a type_proto::Tensor> {
    match value.r#type.as_ref().and_then(|kind| kind.value.as_ref()) {
        Some(type_proto::Value::TensorType(tensor)) => Ok(tensor),
        None => Err(anyhow!(
            "{description} {:?} must declare a tensor type",
            value.name
        )),
    }
}

fn tensor_dimensions<'a>(
    value: &ValueInfoProto,
    tensor: &'a type_proto::Tensor,
    description: &str,
) -> Result<&'a [tensor_shape_proto::Dimension]> {
    tensor
        .shape
        .as_ref()
        .map(|shape| shape.dim.as_slice())
        .ok_or_else(|| anyhow!("{description} {:?} must declare a shape", value.name))
}

fn validate_input_tensor(input: &ValueInfoProto) -> Result<()> {
    let tensor = tensor_type(input, "token model input")?;
    if tensor.elem_type != tensor_proto::DataType::Int64 as i32 {
        return Err(anyhow!("token model input {:?} must use int64", input.name));
    }
    let dimensions = tensor_dimensions(input, tensor, "token model input")?;
    if dimensions.len() != 2 {
        return Err(anyhow!(
            "token model input {:?} must have rank 2",
            input.name
        ));
    }
    validate_batch_dimension(&dimensions[0], "token model input", &input.name)?;
    validate_dynamic_sequence_dimension(&dimensions[1], "token model input", &input.name)
}

fn validate_output_tensor(output: &ValueInfoProto) -> Result<()> {
    let tensor = tensor_type(output, "token model output")?;
    if tensor.elem_type != tensor_proto::DataType::Float as i32 {
        return Err(anyhow!("token model output must use float32"));
    }
    let dimensions = tensor_dimensions(output, tensor, "token model output")?;
    if dimensions.len() != 3 {
        return Err(anyhow!(
            "token model output must have shape [1, sequence, 2]"
        ));
    }
    validate_batch_dimension(&dimensions[0], "token model output", &output.name)?;
    validate_dynamic_sequence_dimension(&dimensions[1], "token model output", &output.name)?;
    if dimensions[2].value != Some(tensor_shape_proto::dimension::Value::DimValue(2)) {
        return Err(anyhow!(
            "token model output must have shape [1, sequence, 2]"
        ));
    }
    Ok(())
}

fn validate_batch_dimension(
    dimension: &tensor_shape_proto::Dimension,
    description: &str,
    name: &str,
) -> Result<()> {
    match dimension.value.as_ref() {
        Some(tensor_shape_proto::dimension::Value::DimValue(1))
        | Some(tensor_shape_proto::dimension::Value::DimParam(_))
        | None => Ok(()),
        Some(tensor_shape_proto::dimension::Value::DimValue(_)) => Err(anyhow!(
            "{description} {name:?} must use batch dimension 1 or a dynamic batch dimension"
        )),
    }
}

fn validate_dynamic_sequence_dimension(
    dimension: &tensor_shape_proto::Dimension,
    description: &str,
    name: &str,
) -> Result<()> {
    if matches!(
        dimension.value,
        Some(tensor_shape_proto::dimension::Value::DimValue(_))
    ) {
        return Err(anyhow!(
            "{description} {name:?} must use a dynamic sequence dimension"
        ));
    }
    Ok(())
}

impl OnnxTokenClassifier {
    /// Load a local token-classification ONNX model and tokenizer.
    ///
    /// `max_model_tokens` includes the model's two special tokens. The
    /// classifier partitions longer inputs into punctuation-aware windows.
    pub fn load(model_path: &Path, tokenizer_path: &Path, max_model_tokens: usize) -> Result<Self> {
        Self::load_with_options(
            model_path,
            tokenizer_path,
            max_model_tokens,
            &LoadOptions::default(),
        )
    }

    /// Load with explicit artifact size guards.
    pub fn load_with_options(
        model_path: &Path,
        tokenizer_path: &Path,
        max_model_tokens: usize,
        options: &LoadOptions,
    ) -> Result<Self> {
        if max_model_tokens < 3 {
            return Err(anyhow!(
                "model window must allow two special tokens and content"
            ));
        }
        check_size_budget(model_path, "model", options.effective_model_limit())?;
        check_size_budget(
            tokenizer_path,
            "tokenizer",
            options.effective_tokenizer_limit(),
        )?;
        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|error| anyhow!("failed to load tokenizer at {tokenizer_path:?}: {error}"))?;
        let tokenizer_contract = prepare_tokenizer(&mut tokenizer)?;
        let onnx = tract_onnx::onnx();
        let model_proto = onnx
            .proto_model_for_path(model_path)
            .with_context(|| format!("failed to parse ONNX model at {model_path:?}"))?;
        crate::reject_external_tensor_data(&model_proto)?;
        validate_token_model_signature(&model_proto)?;
        let model = onnx
            .model_for_proto_model(&model_proto)
            .context("failed to translate ONNX token-classification model")?
            .into_optimized()
            .context("failed to optimise ONNX token-classification model")?
            .into_runnable()
            .context("failed to make ONNX token-classification model runnable")?;
        Ok(Self {
            model,
            tokenizer,
            tokenizer_contract,
            max_model_tokens,
        })
    }

    /// Compress text by retaining the highest-scoring complete source words.
    pub fn compress(
        &self,
        text: &str,
        target: TokenCompressionTarget,
    ) -> Result<TokenCompressionOutput> {
        self.compress_with_limits(text, target, TokenCompressionLimits::default())
    }

    /// Compress with explicit bounds on tokenizer and model-inference work.
    pub fn compress_with_limits(
        &self,
        text: &str,
        target: TokenCompressionTarget,
        limits: TokenCompressionLimits,
    ) -> Result<TokenCompressionOutput> {
        if text.is_empty() {
            return Err(anyhow!("compression input is empty"));
        }
        validate_compression_work(0, 0, limits)?;
        let full_encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|error| anyhow!("tokenizer encode failed: {error}"))?;
        if full_encoding.is_empty() {
            return Err(anyhow!("tokenizer produced empty encoding"));
        }
        let original_tokens = full_encoding.len();
        validate_compression_work(original_tokens, 0, limits)?;
        let budget = target_budget(original_tokens, target)?;
        if budget >= original_tokens {
            return Ok(TokenCompressionOutput {
                text: text.to_string(),
                original_tokens,
                compressed_tokens: original_tokens,
            });
        }

        let boundaries = encoding_observations(text, &full_encoding, 0, None)?;
        let windows = partition_windows(text, &boundaries, self.max_model_tokens)?;
        validate_compression_work(original_tokens, windows.len(), limits)?;
        let mut words = Vec::new();
        for window in windows {
            let byte_start = boundaries[window.start].start;
            let byte_end = boundaries[window.end - 1].end;
            let window_text = &text[byte_start..byte_end];
            let encoding = self
                .tokenizer
                .encode(window_text, true)
                .map_err(|error| anyhow!("tokenizer window encode failed: {error}"))?;
            if encoding.len() > self.max_model_tokens {
                return Err(anyhow!(
                    "encoded window has {} tokens, exceeding model window {}",
                    encoding.len(),
                    self.max_model_tokens
                ));
            }
            if encoding.is_empty() {
                return Err(anyhow!("tokenizer produced an empty model window"));
            }
            let keep_probabilities = self.run_window(&encoding)?;
            let observations =
                encoding_observations(text, &encoding, byte_start, Some(&keep_probabilities))?;
            let window_words = aggregate_word_scores(text, &observations, words.len())?;
            words.extend(window_words);
        }
        if words.is_empty() {
            return Err(anyhow!("token classifier produced no scored source words"));
        }

        let (output, _attempts) = select_with_bounded_token_correction(
            text,
            &words,
            original_tokens,
            target,
            self.tokenizer_contract,
            |candidate| self.count_tokens(candidate),
        )?;
        Ok(output)
    }

    fn count_tokens(&self, text: &str) -> Result<usize> {
        self.tokenizer
            .encode(text, false)
            .map(|encoding| encoding.len())
            .map_err(|error| anyhow!("tokenizer result encode failed: {error}"))
    }

    fn run_window(&self, encoding: &Encoding) -> Result<Vec<f32>> {
        let sequence_len = encoding.len();
        let ids = encoding
            .get_ids()
            .iter()
            .map(|id| i64::from(*id))
            .collect::<Vec<_>>();
        let mask = encoding
            .get_attention_mask()
            .iter()
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        let input_ids = tract_ndarray::Array2::from_shape_vec((1, sequence_len), ids)
            .map_err(|error| anyhow!(error))?;
        let attention_mask = tract_ndarray::Array2::from_shape_vec((1, sequence_len), mask)
            .map_err(|error| anyhow!(error))?;
        let input_names = self
            .model
            .model()
            .input_outlets()?
            .iter()
            .map(|outlet| self.model.model().node(outlet.node).name.clone())
            .collect::<Vec<_>>();
        let mut inputs: TVec<TValue> = tvec!();
        for name in &input_names {
            match token_model_input(name) {
                Some(TokenModelInput::InputIds) => {
                    inputs.push(input_ids.clone().into_tensor().into());
                }
                Some(TokenModelInput::AttentionMask) => {
                    inputs.push(attention_mask.clone().into_tensor().into());
                }
                Some(TokenModelInput::TokenTypeIds) => {
                    let token_types = tract_ndarray::Array2::from_shape_vec(
                        (1, sequence_len),
                        vec![0_i64; sequence_len],
                    )
                    .map_err(|error| anyhow!(error))?;
                    inputs.push(token_types.into_tensor().into());
                }
                None => {
                    return Err(anyhow!(
                        "loaded token model declared unsupported input {name:?}"
                    ));
                }
            }
        }
        let outputs = self
            .model
            .run(inputs)
            .map_err(|error| anyhow!("ONNX token inference failed: {error}"))?;
        let logits = outputs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("ONNX token model returned no outputs"))?;
        let view = logits
            .to_array_view::<f32>()
            .map_err(|error| anyhow!("token logits were not f32: {error}"))?;
        let shape = view.shape().to_vec();
        let flat = view.iter().copied().collect::<Vec<_>>();
        keep_probabilities_from_logits(&flat, &shape, sequence_len)
    }
}

fn prepare_tokenizer(tokenizer: &mut Tokenizer) -> Result<BoundarySeparableTokenizer> {
    tokenizer
        .with_truncation(None)
        .map_err(|error| anyhow!("failed to disable tokenizer truncation: {error}"))?;
    tokenizer.with_padding(None);

    if tokenizer
        .get_added_vocabulary()
        .get_added_tokens_decoder()
        .values()
        .any(|token| !token.special)
    {
        return Err(anyhow!(
            "token compression tokenizer contains non-special added tokens"
        ));
    }

    let post_processor = tokenizer.get_post_processor().ok_or_else(|| {
        anyhow!("token compression tokenizer must add exactly two single-input model tokens")
    })?;
    if post_processor.added_tokens(false) != 2 {
        return Err(anyhow!(
            "token compression tokenizer must add exactly two single-input model tokens"
        ));
    }

    let contract = match (
        tokenizer.get_model(),
        tokenizer.get_normalizer(),
        tokenizer.get_pre_tokenizer(),
    ) {
        (
            ModelWrapper::WordPiece(_),
            Some(NormalizerWrapper::BertNormalizer(normalizer)),
            Some(PreTokenizerWrapper::BertPreTokenizer(_)),
        ) if normalizer.clean_text
            && normalizer.handle_chinese_chars
            && normalizer.strip_accents.is_none()
            && !normalizer.lowercase =>
        {
            BoundarySeparableTokenizer::BertWordPiece
        }
        (
            ModelWrapper::Unigram(_),
            Some(NormalizerWrapper::Precompiled(_)),
            Some(PreTokenizerWrapper::Sequence(sequence)),
        ) if matches!(
            sequence.get_pre_tokenizers(),
            [
                PreTokenizerWrapper::WhitespaceSplit(_),
                PreTokenizerWrapper::Metaspace(metaspace)
            ] if metaspace.get_replacement() == '▁'
                && metaspace.get_prepend_scheme() == PrependScheme::Always
                && metaspace.get_split()
        ) =>
        {
            BoundarySeparableTokenizer::XlmRobertaUnigram
        }
        _ => {
            return Err(anyhow!(
                "unsupported token compression tokenizer: expected the official LLMLingua-2 \
                 mBERT WordPiece or XLM-R Unigram pipeline"
            ));
        }
    };

    // Special-token literals in user text must pass through the validated
    // model pipeline instead of the added-token matcher.
    tokenizer.set_encode_special_tokens(true);
    Ok(contract)
}

fn encoding_observations(
    source: &str,
    encoding: &Encoding,
    byte_base: usize,
    keep_probabilities: Option<&[f32]>,
) -> Result<Vec<TokenObservation>> {
    if keep_probabilities.is_some_and(|probabilities| probabilities.len() != encoding.len()) {
        return Err(anyhow!(
            "token probability count does not match tokenizer encoding"
        ));
    }
    let mut observations = Vec::new();
    for index in 0..encoding.len() {
        if encoding.get_special_tokens_mask()[index] != 0 {
            continue;
        }
        let (relative_start, relative_end) = encoding.get_offsets()[index];
        if relative_start == relative_end {
            continue;
        }
        let observation = TokenObservation {
            start: byte_base
                .checked_add(relative_start)
                .ok_or_else(|| anyhow!("token start offset overflow"))?,
            end: byte_base
                .checked_add(relative_end)
                .ok_or_else(|| anyhow!("token end offset overflow"))?,
            word_id: encoding.get_word_ids()[index],
            keep_probability: keep_probabilities.map_or(0.5, |values| values[index]),
        };
        validate_observation(source, &observation)?;
        observations.push(observation);
    }
    if observations.is_empty() {
        return Err(anyhow!("tokenizer produced no source-aligned tokens"));
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_word_scores, encoding_observations, keep_probabilities_from_logits,
        partition_windows, prepare_tokenizer, reconstruct_ranked_prefix, select_and_reconstruct,
        select_with_bounded_token_correction, validate_compression_work,
        validate_token_model_signature, BoundarySeparableTokenizer, OnnxTokenClassifier,
        TokenCompressionLimitError, TokenCompressionLimits, TokenCompressionTarget,
        TokenObservation, WordScore, MAX_BUDGET_CORRECTION_ATTEMPTS,
    };
    use prost_011::Message as _;
    use std::collections::HashMap;
    use std::path::Path;
    use tokenizers::models::unigram::Unigram;
    use tokenizers::models::wordlevel::WordLevel;
    use tokenizers::models::wordpiece::WordPiece;
    use tokenizers::normalizers::{BertNormalizer, Precompiled};
    use tokenizers::pre_tokenizers::bert::BertPreTokenizer;
    use tokenizers::pre_tokenizers::metaspace::{Metaspace, PrependScheme};
    use tokenizers::pre_tokenizers::sequence::Sequence;
    use tokenizers::pre_tokenizers::whitespace::WhitespaceSplit;
    use tokenizers::pre_tokenizers::PreTokenizerWrapper;
    use tokenizers::processors::bert::BertProcessing;
    use tokenizers::processors::roberta::RobertaProcessing;
    use tokenizers::{AddedToken, PaddingParams, Tokenizer, TruncationParams};
    use tract_onnx::pb::{
        tensor_proto, tensor_shape_proto, type_proto, GraphProto, ModelProto,
        StringStringEntryProto, TensorProto, TensorShapeProto, TypeProto, ValueInfoProto,
    };

    fn dimension(value: tensor_shape_proto::dimension::Value) -> tensor_shape_proto::Dimension {
        tensor_shape_proto::Dimension {
            value: Some(value),
            ..Default::default()
        }
    }

    fn value_info(
        name: &str,
        element_type: tensor_proto::DataType,
        dimensions: Vec<tensor_shape_proto::Dimension>,
    ) -> ValueInfoProto {
        ValueInfoProto {
            name: name.to_string(),
            r#type: Some(TypeProto {
                value: Some(type_proto::Value::TensorType(type_proto::Tensor {
                    elem_type: element_type as i32,
                    shape: Some(TensorShapeProto { dim: dimensions }),
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn bert_wordpiece_tokenizer() -> Tokenizer {
        let vocab = [
            ("[UNK]".to_string(), 0),
            ("[CLS]".to_string(), 1),
            ("[SEP]".to_string(), 2),
            ("a".to_string(), 3),
            ("b".to_string(), 4),
            ("c".to_string(), 5),
            ("d".to_string(), 6),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        let model = WordPiece::builder()
            .vocab(vocab)
            .unk_token("[UNK]".to_string())
            .build()
            .expect("wordpiece fixture");
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_normalizer(Some(BertNormalizer::new(true, true, None, false)));
        tokenizer.with_pre_tokenizer(Some(BertPreTokenizer));
        tokenizer.add_special_tokens(&[
            AddedToken::from("[CLS]", true),
            AddedToken::from("[SEP]", true),
        ]);
        tokenizer.with_post_processor(Some(BertProcessing::new(
            ("[SEP]".to_string(), 2),
            ("[CLS]".to_string(), 1),
        )));
        tokenizer
    }

    fn xlm_roberta_unigram_tokenizer(prepend_scheme: PrependScheme) -> Tokenizer {
        let model = Unigram::from(
            vec![
                ("<unk>".to_string(), 0.0),
                ("<s>".to_string(), -0.1),
                ("</s>".to_string(), -0.1),
                ("▁".to_string(), -0.2),
                ("a".to_string(), -0.3),
                ("b".to_string(), -0.3),
                ("c".to_string(), -0.3),
                ("d".to_string(), -0.3),
            ],
            Some(0),
            false,
        )
        .expect("unigram fixture");
        let mut tokenizer = Tokenizer::new(model);
        let mut precompiled_charsmap = Vec::with_capacity(4 + 256 * 4);
        precompiled_charsmap.extend_from_slice(&(256_u32 * 4).to_le_bytes());
        precompiled_charsmap.extend(std::iter::repeat_n(0_u8, 256 * 4));
        let normalizer =
            Precompiled::from(&precompiled_charsmap).expect("identity precompiled normalizer");
        tokenizer.with_normalizer(Some(normalizer));
        tokenizer.with_pre_tokenizer(Some(Sequence::new(vec![
            PreTokenizerWrapper::WhitespaceSplit(WhitespaceSplit),
            PreTokenizerWrapper::Metaspace(Metaspace::new('▁', prepend_scheme, true)),
        ])));
        tokenizer.add_special_tokens(&[
            AddedToken::from("<s>", true),
            AddedToken::from("</s>", true),
        ]);
        tokenizer.with_post_processor(Some(RobertaProcessing::new(
            ("</s>".to_string(), 2),
            ("<s>".to_string(), 1),
        )));
        tokenizer
    }

    fn assert_reconstructed_extensions_are_monotone(mut tokenizer: Tokenizer, source: &str) {
        prepare_tokenizer(&mut tokenizer).expect("validated tokenizer fixture");
        let encoding = tokenizer.encode(source, false).expect("encode source");
        let observations =
            encoding_observations(source, &encoding, 0, None).expect("source observations");
        let words = aggregate_word_scores(source, &observations, 0).expect("aggregate words");
        assert!(
            (2..=12).contains(&words.len()),
            "fixture must remain small enough for exhaustive subsets: {} words",
            words.len()
        );

        let subset_count = 1_usize << words.len();
        for mask in 1..subset_count {
            let selected = words
                .iter()
                .enumerate()
                .filter_map(|(index, word)| ((mask & (1 << index)) != 0).then_some(*word))
                .collect::<Vec<_>>();
            let base = reconstruct_ranked_prefix(source, &selected, selected.len(), encoding.len())
                .expect("reconstruct subset");
            let base_tokens = tokenizer
                .encode(base.text, false)
                .expect("encode subset")
                .len();

            for (index, word) in words.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    continue;
                }
                let mut extended = selected.clone();
                extended.push(*word);
                let extended =
                    reconstruct_ranked_prefix(source, &extended, extended.len(), encoding.len())
                        .expect("reconstruct extended subset");
                let extended_tokens = tokenizer
                    .encode(extended.text, false)
                    .expect("encode extended subset")
                    .len();
                assert!(
                    extended_tokens >= base_tokens,
                    "adding source span {index} reduced tokens: {base_tokens} -> \
                     {extended_tokens} for {source:?}"
                );
            }
        }
    }

    fn valid_signature_model() -> ModelProto {
        let batch = || dimension(tensor_shape_proto::dimension::Value::DimValue(1));
        let sequence = || {
            dimension(tensor_shape_proto::dimension::Value::DimParam(
                "sequence".to_string(),
            ))
        };
        ModelProto {
            graph: Some(GraphProto {
                input: vec![
                    value_info(
                        "input_ids",
                        tensor_proto::DataType::Int64,
                        vec![batch(), sequence()],
                    ),
                    value_info(
                        "attention_mask",
                        tensor_proto::DataType::Int64,
                        vec![batch(), sequence()],
                    ),
                ],
                output: vec![value_info(
                    "logits",
                    tensor_proto::DataType::Float,
                    vec![
                        batch(),
                        sequence(),
                        dimension(tensor_shape_proto::dimension::Value::DimValue(2)),
                    ],
                )],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn load_fixture_model(model: &ModelProto) -> anyhow::Error {
        let directory = tempfile::tempdir().expect("tempdir");
        let model_path = directory.path().join("token-model.onnx");
        let tokenizer_path = directory.path().join("tokenizer.json");
        std::fs::write(&model_path, model.encode_to_vec()).expect("write model fixture");
        bert_wordpiece_tokenizer()
            .save(&tokenizer_path, false)
            .expect("write tokenizer fixture");

        OnnxTokenClassifier::load(&model_path, &tokenizer_path, 512)
            .err()
            .expect("fixture must be rejected")
    }

    fn word(
        source: &str,
        value: &str,
        score: f32,
        token_count: usize,
        ordinal: usize,
    ) -> WordScore {
        let start = source.find(value).expect("fixture word");
        WordScore {
            start,
            end: start + value.len(),
            score,
            token_count,
            ordinal,
        }
    }

    #[test]
    fn ratio_selection_ranks_by_score_and_restores_source_order() {
        let source = "one two three four";
        let words = vec![
            word(source, "one", 0.5, 1, 0),
            word(source, "two", 0.9, 1, 1),
            word(source, "three", 0.4, 1, 2),
            word(source, "four", 0.8, 1, 3),
        ];

        let output =
            select_and_reconstruct(source, &words, 4, TokenCompressionTarget::RetainRatio(0.5))
                .expect("selection");

        assert_eq!(output.text, "two four");
        assert_eq!(output.original_tokens, 4);
        assert_eq!(output.compressed_tokens, 2);
    }

    #[test]
    fn equal_scores_break_ties_by_original_ordinal() {
        let source = "one two three four";
        let words = vec![
            word(source, "one", 0.5, 1, 0),
            word(source, "two", 0.5, 1, 1),
            word(source, "three", 0.5, 1, 2),
            word(source, "four", 0.5, 1, 3),
        ];

        let output =
            select_and_reconstruct(source, &words, 4, TokenCompressionTarget::TargetTokens(2))
                .expect("selection");

        assert_eq!(output.text, "one two");
    }

    #[test]
    fn target_mode_skips_a_word_that_cannot_fit_the_budget() {
        let source = "international cat dog";
        let words = vec![
            word(source, "international", 1.0, 3, 0),
            word(source, "cat", 0.9, 1, 1),
            word(source, "dog", 0.8, 1, 2),
        ];

        let output =
            select_and_reconstruct(source, &words, 5, TokenCompressionTarget::TargetTokens(2))
                .expect("selection");

        assert_eq!(output.text, "cat dog");
        assert_eq!(output.compressed_tokens, 2);
    }

    #[test]
    fn punctuation_correction_is_bounded_for_a_large_token_target() {
        const WORD_COUNT: usize = 32_768;
        const PUNCTUATION_TOKENS: usize = 8_192;

        let mut source = String::with_capacity(WORD_COUNT * 2 + PUNCTUATION_TOKENS);
        let mut words = Vec::with_capacity(WORD_COUNT);
        for ordinal in 0..WORD_COUNT {
            if ordinal > 0 {
                source.push(' ');
            }
            let start = source.len();
            source.push('w');
            words.push(WordScore {
                start,
                end: source.len(),
                score: 0.5,
                token_count: 1,
                ordinal,
            });
        }
        source.extend(std::iter::repeat_n('!', PUNCTUATION_TOKENS));

        let observed_attempts = std::cell::Cell::new(0);
        let (output, attempts) = select_with_bounded_token_correction(
            &source,
            &words,
            WORD_COUNT + 1,
            TokenCompressionTarget::TargetTokens(WORD_COUNT),
            BoundarySeparableTokenizer::BertWordPiece,
            |candidate| {
                observed_attempts.set(observed_attempts.get() + 1);
                Ok(candidate.bytes().filter(|byte| *byte == b'w').count()
                    + candidate.bytes().filter(|byte| *byte == b'!').count())
            },
        )
        .expect("a smaller ranked prefix fits without the punctuation suffix");

        assert_eq!(attempts, observed_attempts.get());
        assert!(attempts > 1);
        assert!(attempts <= MAX_BUDGET_CORRECTION_ATTEMPTS);
        assert!(output.compressed_tokens <= WORD_COUNT);
        assert!(!output.text.contains('!'));
        let mut source_characters = source.chars();
        assert!(output
            .text
            .chars()
            .all(|wanted| source_characters.by_ref().any(|found| found == wanted)));
    }

    #[test]
    fn correction_uses_an_undecorated_word_when_terminal_punctuation_exceeds_budget() {
        let source = "a!!!!";
        let words = vec![word(source, "a", 1.0, 1, 0)];
        let mut tokenizer = bert_wordpiece_tokenizer();
        let contract = prepare_tokenizer(&mut tokenizer).expect("validated tokenizer");
        let original_tokens = tokenizer
            .encode(source, false)
            .expect("encode source")
            .len();

        let (output, attempts) = select_with_bounded_token_correction(
            source,
            &words,
            original_tokens,
            TokenCompressionTarget::TargetTokens(1),
            contract,
            |candidate| {
                tokenizer
                    .encode(candidate, false)
                    .map(|encoding| encoding.len())
                    .map_err(|error| anyhow::anyhow!(error))
            },
        )
        .expect("the complete undecorated top word fits");

        assert_eq!(output.text, "a");
        assert_eq!(output.compressed_tokens, 1);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn reconstruction_is_unicode_offset_safe() {
        let source = "naïve  café 東京";
        let words = vec![
            word(source, "naïve", 0.9, 1, 0),
            word(source, "café", 0.1, 1, 1),
            word(source, "東京", 0.8, 1, 2),
        ];

        let output =
            select_and_reconstruct(source, &words, 3, TokenCompressionTarget::TargetTokens(2))
                .expect("selection");

        assert_eq!(output.text, "naïve  東京");
    }

    #[test]
    fn reconstruction_preserves_source_separators_and_terminal_punctuation() {
        let source = "Alpha, noisy beta.\nGamma!";
        let words = vec![
            word(source, "Alpha", 0.9, 1, 0),
            word(source, "noisy", 0.1, 1, 1),
            word(source, "beta", 0.2, 1, 2),
            word(source, "Gamma", 0.8, 1, 3),
        ];

        let output =
            select_and_reconstruct(source, &words, 4, TokenCompressionTarget::TargetTokens(2))
                .expect("selection");

        assert_eq!(output.text, "Alpha, Gamma!");
    }

    #[test]
    fn word_score_is_the_mean_of_its_subtoken_keep_probabilities() {
        let observations = vec![
            TokenObservation {
                start: 0,
                end: 2,
                word_id: Some(0),
                keep_probability: 0.8,
            },
            TokenObservation {
                start: 2,
                end: 12,
                word_id: Some(0),
                keep_probability: 0.4,
            },
            TokenObservation {
                start: 13,
                end: 16,
                word_id: Some(1),
                keep_probability: 0.9,
            },
        ];

        let words = aggregate_word_scores("unbelievable cat", &observations, 0)
            .expect("valid observations");

        assert_eq!(words.len(), 2);
        assert!((words[0].score - 0.6).abs() < 1e-6);
        assert_eq!(words[0].token_count, 2);
        assert_eq!((words[0].start, words[0].end), (0, 12));
    }

    #[test]
    fn overlapping_offsets_within_one_tokenizer_word_are_unioned() {
        // XLM-R's normalizer can emit multiple subtokens for one source word
        // whose aligned offsets overlap. For example, the official
        // LLMLingua-2 tokenizer aligns "東京" as 0..3 and 0..6.
        let observations = vec![
            TokenObservation {
                start: 0,
                end: 3,
                word_id: Some(0),
                keep_probability: 0.8,
            },
            TokenObservation {
                start: 0,
                end: 6,
                word_id: Some(0),
                keep_probability: 0.4,
            },
        ];

        let words =
            aggregate_word_scores("東京", &observations, 0).expect("same-word overlap is valid");

        assert_eq!(words.len(), 1);
        assert_eq!((words[0].start, words[0].end), (0, 6));
        assert_eq!(words[0].token_count, 2);
        assert!((words[0].score - 0.6).abs() < 1e-6);
    }

    #[test]
    fn window_partition_accepts_overlapping_offsets_within_one_tokenizer_word() {
        let observations = vec![
            TokenObservation::boundary(0, 3, Some(0)),
            TokenObservation::boundary(0, 6, Some(0)),
        ];

        let windows =
            partition_windows("東京", &observations, 4).expect("same-word overlap is valid");

        assert_eq!(windows, vec![0..2]);
    }

    #[test]
    fn window_partition_prefers_punctuation_without_exceeding_model_limit() {
        let source = "one two. three four five";
        let observations = vec![
            TokenObservation::boundary(0, 3, Some(0)),
            TokenObservation::boundary(4, 7, Some(1)),
            TokenObservation::boundary(7, 8, Some(2)),
            TokenObservation::boundary(9, 14, Some(3)),
            TokenObservation::boundary(15, 19, Some(4)),
            TokenObservation::boundary(20, 24, Some(5)),
        ];

        let windows = partition_windows(source, &observations, 5).expect("valid windows");

        assert_eq!(windows, vec![0..3, 3..6]);
    }

    #[test]
    fn window_partition_rejects_a_word_larger_than_the_content_window() {
        let observations = vec![
            TokenObservation::boundary(0, 4, Some(0)),
            TokenObservation::boundary(4, 8, Some(0)),
        ];

        let error = partition_windows("abcdefgh", &observations, 3)
            .expect_err("two-subtoken word cannot fit one content token");

        assert!(error.to_string().contains("word exceeds model window"));
    }

    #[test]
    fn invalid_targets_are_rejected() {
        let source = "one";
        let words = vec![word(source, "one", 1.0, 1, 0)];

        for target in [
            TokenCompressionTarget::RetainRatio(0.0),
            TokenCompressionTarget::RetainRatio(f64::NAN),
            TokenCompressionTarget::RetainRatio(1.1),
            TokenCompressionTarget::TargetTokens(0),
        ] {
            assert!(
                select_and_reconstruct(source, &words, 1, target).is_err(),
                "target must fail: {target:?}"
            );
        }
    }

    #[test]
    fn token_logits_softmax_the_two_class_axis() {
        let logits = [0.0, 0.0, 0.0, 2.0_f32.ln()];

        let probabilities =
            keep_probabilities_from_logits(&logits, &[1, 2, 2], 2).expect("valid logits");

        assert_eq!(probabilities.len(), 2);
        assert!((probabilities[0] - 0.5).abs() < 1e-6);
        assert!((probabilities[1] - (2.0 / 3.0)).abs() < 1e-6);
    }

    #[test]
    fn token_logits_reject_any_shape_other_than_batch_sequence_two() {
        let error = keep_probabilities_from_logits(&[0.0; 6], &[1, 2, 3], 2)
            .expect_err("three-class logits are unsupported");

        assert!(error.to_string().contains("expected [1, 2, 2]"));
    }

    #[test]
    fn token_classifier_rejects_an_impossibly_small_window_before_loading_files() {
        let error = OnnxTokenClassifier::load(
            Path::new("missing-model.onnx"),
            Path::new("missing-tokenizer.json"),
            2,
        )
        .err()
        .expect("window cannot fit two special tokens plus content");

        assert!(error.to_string().contains("model window"));
    }

    #[test]
    fn compression_work_limits_bound_tokens_and_windows() {
        let limits = TokenCompressionLimits {
            max_input_tokens: 10,
            max_windows: 2,
        };

        validate_compression_work(10, 2, limits).expect("limits are inclusive");
        let token_error =
            validate_compression_work(11, 1, limits).expect_err("token limit must reject");
        assert!(token_error.to_string().contains("input token limit"));
        assert!(token_error
            .downcast_ref::<TokenCompressionLimitError>()
            .is_some());
        let window_error =
            validate_compression_work(10, 3, limits).expect_err("window limit must reject");
        assert!(window_error.to_string().contains("inference window limit"));
        assert!(window_error
            .downcast_ref::<TokenCompressionLimitError>()
            .is_some());
    }

    #[test]
    fn token_classifier_disables_serialized_truncation_and_padding() {
        let mut tokenizer = bert_wordpiece_tokenizer();
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: 4,
                ..TruncationParams::default()
            }))
            .expect("valid truncation fixture");
        tokenizer.with_padding(Some(PaddingParams::default()));

        prepare_tokenizer(&mut tokenizer).expect("prepare tokenizer");

        assert!(tokenizer.get_truncation().is_none());
        assert!(tokenizer.get_padding().is_none());
    }

    #[test]
    fn official_llmlingua_tokenizer_families_are_boundary_separable() {
        let mut bert = bert_wordpiece_tokenizer();
        let bert_contract =
            prepare_tokenizer(&mut bert).expect("official mBERT tokenizer structure");
        assert_eq!(bert_contract, BoundarySeparableTokenizer::BertWordPiece);
        assert!(bert.get_encode_special_tokens());

        let mut xlm = xlm_roberta_unigram_tokenizer(PrependScheme::Always);
        let xlm_contract = prepare_tokenizer(&mut xlm).expect("official XLM-R tokenizer structure");
        assert_eq!(xlm_contract, BoundarySeparableTokenizer::XlmRobertaUnigram);
        assert!(xlm.get_encode_special_tokens());
    }

    #[test]
    fn validated_tokenizers_keep_punctuation_and_unicode_prefix_counts_monotone() {
        let source = "a—東京 b! c";
        assert_reconstructed_extensions_are_monotone(bert_wordpiece_tokenizer(), source);
        assert_reconstructed_extensions_are_monotone(
            xlm_roberta_unigram_tokenizer(PrependScheme::Always),
            source,
        );
    }

    #[test]
    fn special_token_literals_are_routed_through_the_validated_model_pipeline() {
        let mut tokenizer = bert_wordpiece_tokenizer();
        prepare_tokenizer(&mut tokenizer).expect("validated tokenizer");

        let encoding = tokenizer.encode("[CLS] a", false).expect("encode literal");

        assert!(encoding
            .get_special_tokens_mask()
            .iter()
            .all(|value| *value == 0));
        assert!(
            encoding.len() > 2,
            "the raw special-token literal must not be matched as one added token"
        );
    }

    #[test]
    fn tokenizer_contract_rejects_non_separable_or_added_token_configs() {
        let mut with_added_token = bert_wordpiece_tokenizer();
        with_added_token.add_tokens(&[AddedToken::from("a b c", false)]);
        let counts = ["a", "a b", "a b c", "a b c d"]
            .map(|text| with_added_token.encode(text, false).expect("encode").len());
        assert!(
            counts[2] < counts[1],
            "the added token creates the reviewer's non-monotone skipped-prefix shape"
        );
        let error = prepare_tokenizer(&mut with_added_token)
            .expect_err("non-special added tokens break boundary separability");
        assert!(error.to_string().contains("non-special added tokens"));

        let mut wrong_model = Tokenizer::new(WordLevel::default());
        assert!(prepare_tokenizer(&mut wrong_model).is_err());

        let mut wrong_metaspace = xlm_roberta_unigram_tokenizer(PrependScheme::First);
        assert!(prepare_tokenizer(&mut wrong_metaspace).is_err());

        let mut wrong_post_processor = bert_wordpiece_tokenizer();
        wrong_post_processor.with_post_processor(Some(
            tokenizers::processors::byte_level::ByteLevel::default(),
        ));
        let error = prepare_tokenizer(&mut wrong_post_processor)
            .expect_err("the model window contract reserves exactly two special tokens");
        assert!(error
            .to_string()
            .contains("exactly two single-input model tokens"));
    }

    #[test]
    fn token_classifier_rejects_external_tensor_data_before_tract_load() {
        let mut model = valid_signature_model();
        model
            .graph
            .as_mut()
            .expect("graph")
            .initializer
            .push(TensorProto {
                name: "external-weight".to_string(),
                dims: vec![1],
                data_type: tensor_proto::DataType::Float as i32,
                data_location: Some(tensor_proto::DataLocation::External as i32),
                external_data: vec![StringStringEntryProto {
                    key: "location".to_string(),
                    value: "../../unbounded-model-data.bin".to_string(),
                }],
                ..Default::default()
            });

        let error = load_fixture_model(&model);

        assert!(
            error.to_string().contains("external tensor data"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn token_classifier_rejects_static_sequence_signatures_at_load() {
        let mut model = valid_signature_model();
        let static_sequence = dimension(tensor_shape_proto::dimension::Value::DimValue(512));
        let graph = model.graph.as_mut().expect("graph");
        for input in &mut graph.input {
            let Some(type_proto::Value::TensorType(tensor)) =
                input.r#type.as_mut().and_then(|kind| kind.value.as_mut())
            else {
                panic!("tensor input");
            };
            tensor.shape.as_mut().expect("shape").dim[1] = static_sequence.clone();
        }

        let error = load_fixture_model(&model);

        assert!(
            error.to_string().contains("dynamic sequence dimension"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn optimum_style_dynamic_batch_onnx_signature_is_accepted() {
        let mut model = valid_signature_model();
        let graph = model.graph.as_mut().expect("graph");
        for value in graph.input.iter_mut().chain(&mut graph.output) {
            let Some(type_proto::Value::TensorType(tensor)) =
                value.r#type.as_mut().and_then(|kind| kind.value.as_mut())
            else {
                panic!("tensor value");
            };
            tensor.shape.as_mut().expect("shape").dim[0] = dimension(
                tensor_shape_proto::dimension::Value::DimParam("batch_size".to_string()),
            );
        }

        validate_token_model_signature(&model)
            .expect("Hugging Face Optimum exports dynamic batch and sequence axes");

        let graph = model.graph.as_mut().expect("graph");
        for value in graph.input.iter_mut().chain(&mut graph.output) {
            let Some(type_proto::Value::TensorType(tensor)) =
                value.r#type.as_mut().and_then(|kind| kind.value.as_mut())
            else {
                panic!("tensor value");
            };
            tensor.shape.as_mut().expect("shape").dim[0].value = None;
        }
        validate_token_model_signature(&model).expect("an unspecified ONNX batch axis is dynamic");
    }

    #[test]
    fn token_classifier_rejects_fixed_batch_greater_than_one() {
        let mut model = valid_signature_model();
        let input = &mut model.graph.as_mut().expect("graph").input[0];
        let Some(type_proto::Value::TensorType(tensor)) =
            input.r#type.as_mut().and_then(|kind| kind.value.as_mut())
        else {
            panic!("tensor input");
        };
        tensor.shape.as_mut().expect("shape").dim[0] =
            dimension(tensor_shape_proto::dimension::Value::DimValue(2));

        let error = validate_token_model_signature(&model)
            .expect_err("fixed multi-batch model must be rejected");
        assert!(error.to_string().contains("batch dimension"));
    }

    #[test]
    fn token_classifier_validates_input_and_output_contract_at_load() {
        let cases = [
            (
                {
                    let mut model = valid_signature_model();
                    model.graph.as_mut().expect("graph").input[0].name = "position_ids".to_string();
                    model
                },
                "unsupported token model input",
            ),
            (
                {
                    let mut model = valid_signature_model();
                    let input = &mut model.graph.as_mut().expect("graph").input[0];
                    let Some(type_proto::Value::TensorType(tensor)) =
                        input.r#type.as_mut().and_then(|kind| kind.value.as_mut())
                    else {
                        panic!("tensor input");
                    };
                    tensor.elem_type = tensor_proto::DataType::Float as i32;
                    model
                },
                "must use int64",
            ),
            (
                {
                    let mut model = valid_signature_model();
                    let input = &mut model.graph.as_mut().expect("graph").input[0];
                    let Some(type_proto::Value::TensorType(tensor)) =
                        input.r#type.as_mut().and_then(|kind| kind.value.as_mut())
                    else {
                        panic!("tensor input");
                    };
                    tensor.shape.as_mut().expect("shape").dim.pop();
                    model
                },
                "must have rank 2",
            ),
            (
                {
                    let mut model = valid_signature_model();
                    let output = &mut model.graph.as_mut().expect("graph").output[0];
                    let Some(type_proto::Value::TensorType(tensor)) =
                        output.r#type.as_mut().and_then(|kind| kind.value.as_mut())
                    else {
                        panic!("tensor output");
                    };
                    tensor.elem_type = tensor_proto::DataType::Int64 as i32;
                    model
                },
                "output must use float32",
            ),
            (
                {
                    let mut model = valid_signature_model();
                    let output = &mut model.graph.as_mut().expect("graph").output[0];
                    let Some(type_proto::Value::TensorType(tensor)) =
                        output.r#type.as_mut().and_then(|kind| kind.value.as_mut())
                    else {
                        panic!("tensor output");
                    };
                    tensor.shape.as_mut().expect("shape").dim[2] =
                        dimension(tensor_shape_proto::dimension::Value::DimValue(3));
                    model
                },
                "output must have shape [1, sequence, 2]",
            ),
        ];

        for (model, expected) in cases {
            let error = load_fixture_model(&model);
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error:#}"
            );
        }
    }

    #[test]
    fn token_classifier_real_model_is_extractively_compressed_when_configured() {
        let (Ok(model), Ok(tokenizer)) = (
            std::env::var("SBPROXY_TEST_TOKEN_MODEL"),
            std::env::var("SBPROXY_TEST_TOKEN_TOKENIZER"),
        ) else {
            eprintln!("skipping: set SBPROXY_TEST_TOKEN_MODEL/_TOKENIZER to run");
            return;
        };
        let classifier = OnnxTokenClassifier::load(Path::new(&model), Path::new(&tokenizer), 512)
            .expect("load token classifier");

        let output = classifier
            .compress(
                "Keep the important evidence and remove the filler.",
                TokenCompressionTarget::RetainRatio(0.5),
            )
            .expect("compress");

        assert!(!output.text.is_empty());
        assert!(output.compressed_tokens <= output.original_tokens);
        let mut source = "Keep the important evidence and remove the filler.".chars();
        assert!(
            output
                .text
                .chars()
                .all(|wanted| source.by_ref().any(|found| found == wanted)),
            "output must be an extractive subsequence"
        );
    }
}
