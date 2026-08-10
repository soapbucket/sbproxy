use bytes::Bytes;

use super::ModelPlaneError;

/// Rewrite the engine-facing model identifier after authenticating the exact body.
pub(crate) fn rewrite_engine_model(
    body: &[u8],
    content_type: Option<&str>,
    engine_model: &str,
    max_body_bytes: usize,
) -> Result<Bytes, ModelPlaneError> {
    if body.len() > max_body_bytes {
        return Err(ModelPlaneError::BodyTooLarge);
    }
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    let is_json = media_type == "application/json" || media_type.ends_with("+json");
    if !is_json {
        if media_type.eq_ignore_ascii_case("multipart/form-data") {
            let boundary = multipart_boundary(content_type.unwrap_or_default())?;
            return rewrite_multipart_model(body, &boundary, engine_model, max_body_bytes);
        }
        return Ok(Bytes::copy_from_slice(body));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ModelPlaneError::InvalidRequest)?;
    let object = value
        .as_object_mut()
        .ok_or(ModelPlaneError::InvalidRequest)?;
    object.insert(
        "model".to_string(),
        serde_json::Value::String(engine_model.to_string()),
    );
    let encoded = serde_json::to_vec(&value).map_err(|_| ModelPlaneError::InvalidRequest)?;
    if encoded.len() > max_body_bytes {
        return Err(ModelPlaneError::BodyTooLarge);
    }
    Ok(Bytes::from(encoded))
}

fn multipart_boundary(content_type: &str) -> Result<Vec<u8>, ModelPlaneError> {
    let boundary = content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"'))
    });
    let boundary = boundary.filter(|value| {
        !value.is_empty()
            && value.len() <= 70
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\r' | b'\n'))
    });
    boundary
        .map(|value| value.as_bytes().to_vec())
        .ok_or(ModelPlaneError::InvalidRequest)
}

fn rewrite_multipart_model(
    body: &[u8],
    boundary: &[u8],
    engine_model: &str,
    max_body_bytes: usize,
) -> Result<Bytes, ModelPlaneError> {
    let model_range =
        multipart_field_range(body, boundary, "model")?.ok_or(ModelPlaneError::InvalidRequest)?;
    let rewritten_length = body
        .len()
        .checked_sub(model_range.len())
        .and_then(|length| length.checked_add(engine_model.len()))
        .ok_or(ModelPlaneError::BodyTooLarge)?;
    if rewritten_length > max_body_bytes {
        return Err(ModelPlaneError::BodyTooLarge);
    }
    let mut rewritten = Vec::with_capacity(rewritten_length);
    rewritten.extend_from_slice(&body[..model_range.start]);
    rewritten.extend_from_slice(engine_model.as_bytes());
    rewritten.extend_from_slice(&body[model_range.end..]);
    Ok(Bytes::from(rewritten))
}

/// Read the bounded public model field from a multipart inference request.
pub(crate) fn multipart_model(
    body: &[u8],
    content_type: &str,
) -> Result<Option<String>, ModelPlaneError> {
    let boundary = multipart_boundary(content_type)?;
    let Some(range) = multipart_field_range(body, &boundary, "model")? else {
        return Ok(None);
    };
    let model = std::str::from_utf8(&body[range])
        .map_err(|_| ModelPlaneError::InvalidRequest)?
        .trim();
    if model.is_empty()
        || model.len() > 128
        || !model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@' | b'/')
        })
    {
        return Err(ModelPlaneError::InvalidRequest);
    }
    Ok(Some(model.to_string()))
}

/// Maximum prompt text handed back for inspection, in bytes.
///
/// Matched to `DEFAULT_MAX_MESSAGE_LEN` in `sbproxy-modules`'
/// `policy::prompt_injection_v2::body_aware`, which truncates every
/// message pulled out of a JSON body to the same 16 KiB before the
/// classifier sees it. Keeping the two equal means a `prompt` sent as a
/// form field reaches the detector with exactly as much text as the
/// same words sent as JSON, so the multipart path is not the cheaper
/// one to hide in. That constant is private to its crate, so the value
/// is repeated here rather than imported.
const MULTIPART_PROMPT_MAX_BYTES: usize = 16 * 1024;

/// Read the `prompt` form field from a multipart inference request as
/// text the input pipeline can scan.
///
/// `POST /v1/images/edits` and `/v1/images/variations` both carry
/// caller-written instructions in this field, and audio transcription
/// accepts it as a decoding hint, so it is the one part of a multipart
/// request that has to reach the guardrails. The image and audio bytes
/// are not text and are not read here.
///
/// A request with no `prompt` part returns `Ok(None)` rather than an
/// error: a plain transcription carries no prompt and is completely
/// ordinary.
///
/// Unlike [`multipart_model`] the text is held to no character
/// allowlist. A model name is a bounded identifier that gets
/// substituted back into a rewritten body, while a prompt is free-form
/// human writing; refusing spaces, punctuation, newlines, or non-ASCII
/// would reject working traffic. It is not trimmed either, so what the
/// scanner reads is what the caller wrote.
pub(crate) fn multipart_prompt(
    body: &[u8],
    content_type: &str,
) -> Result<Option<String>, ModelPlaneError> {
    let boundary = multipart_boundary(content_type)?;
    let Some(range) = multipart_field_range(body, &boundary, "prompt")? else {
        return Ok(None);
    };
    // Bound the slice before decoding, not the string after: a caller
    // who posts a megabyte of prose should not get a megabyte-sized
    // allocation out of this, and truncating is the right answer rather
    // than an error because refusing a long prompt outright would break
    // requests that work today.
    let end = range
        .end
        .min(range.start.saturating_add(MULTIPART_PROMPT_MAX_BYTES));
    let bounded = body
        .get(range.start..end)
        .ok_or(ModelPlaneError::InvalidRequest)?;
    // Lossy rather than `InvalidRequest`, for two reasons. The consumer
    // is a classifier that needs something to read, and rejecting the
    // request over one bad byte would hand a caller a way to skip the
    // scan by sending one. Cutting at the cap above can also split a
    // multi-byte character at the tail, and that is a prompt that was
    // perfectly valid on the wire, so it must not fail here.
    Ok(Some(String::from_utf8_lossy(bounded).into_owned()))
}

/// Locate the body range of one named part in a multipart form body.
///
/// Every multipart reader in this file walks the parts through here. A
/// second boundary parser would be free to disagree with this one about
/// where a part starts and ends, and a scanner that reads a different
/// span than the one forwarded upstream is worse than no scanner at
/// all, so the field name is a parameter instead of the walk being
/// copied per field.
///
/// A field that appears twice is refused. The upstream provider picks
/// one of the two by a rule of its own, so a reader here would have to
/// guess, and a caller who guessed differently could show one value to
/// the proxy and send another to the model.
fn multipart_field_range(
    body: &[u8],
    boundary: &[u8],
    field: &str,
) -> Result<Option<std::ops::Range<usize>>, ModelPlaneError> {
    let mut delimiter = Vec::with_capacity(boundary.len() + 2);
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(boundary);
    let mut next_delimiter = Vec::with_capacity(boundary.len() + 4);
    next_delimiter.extend_from_slice(b"\r\n");
    next_delimiter.extend_from_slice(&delimiter);

    let mut cursor = 0usize;
    let mut field_range = None;
    let mut saw_closing = false;
    while body
        .get(cursor..)
        .is_some_and(|tail| tail.starts_with(&delimiter))
    {
        cursor = cursor.saturating_add(delimiter.len());
        if body
            .get(cursor..)
            .is_some_and(|tail| tail.starts_with(b"--"))
        {
            saw_closing = true;
            break;
        }
        if !body
            .get(cursor..)
            .is_some_and(|tail| tail.starts_with(b"\r\n"))
        {
            return Err(ModelPlaneError::InvalidRequest);
        }
        cursor += 2;
        let header_length =
            find_bytes(&body[cursor..], b"\r\n\r\n").ok_or(ModelPlaneError::InvalidRequest)?;
        let headers = body
            .get(cursor..cursor + header_length)
            .ok_or(ModelPlaneError::InvalidRequest)?;
        let part_start = cursor + header_length + 4;
        let part_length = find_bytes(
            body.get(part_start..)
                .ok_or(ModelPlaneError::InvalidRequest)?,
            &next_delimiter,
        )
        .ok_or(ModelPlaneError::InvalidRequest)?;
        let part_end = part_start + part_length;
        if multipart_field_name(headers).as_deref() == Some(field)
            && field_range.replace(part_start..part_end).is_some()
        {
            return Err(ModelPlaneError::InvalidRequest);
        }
        cursor = part_end + 2;
    }
    if !saw_closing {
        return Err(ModelPlaneError::InvalidRequest);
    }
    Ok(field_range)
}

fn multipart_field_name(headers: &[u8]) -> Option<String> {
    let headers = std::str::from_utf8(headers).ok()?;
    let disposition = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-disposition")
            .then_some(value)
    })?;
    disposition.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("name")
            .then(|| value.trim().trim_matches('"').to_string())
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_only_the_multipart_model_field() {
        let body = b"--test-boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\npublic/whisper\r\n--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nmodel=public/whisper\0audio\r\n--test-boundary--\r\n";
        let rewritten = rewrite_engine_model(
            body,
            Some("multipart/form-data; boundary=test-boundary"),
            "whisper-worker",
            1024 * 1024,
        )
        .expect("multipart rewrite");
        let text = String::from_utf8_lossy(&rewritten);

        assert!(text.contains("name=\"model\"\r\n\r\nwhisper-worker\r\n"));
        assert!(text.contains("model=public/whisper\0audio"));
        assert!(!text.contains("\r\n\r\npublic/whisper\r\n"));
        assert_eq!(
            multipart_model(body, "multipart/form-data; boundary=\"test-boundary\"")
                .expect("read model")
                .as_deref(),
            Some("public/whisper")
        );
    }

    #[test]
    fn rejects_multipart_without_a_model_field() {
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\naudio\r\n--b--\r\n";
        assert!(matches!(
            rewrite_engine_model(
                body,
                Some("multipart/form-data; boundary=b"),
                "whisper-worker",
                1024,
            ),
            Err(ModelPlaneError::InvalidRequest)
        ));
    }

    #[test]
    fn reads_the_multipart_prompt_field() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nmake the sky green\r\n--b\r\nContent-Disposition: form-data; name=\"image\"; filename=\"cat.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n--b--\r\n";
        assert_eq!(
            multipart_prompt(body, "multipart/form-data; boundary=b")
                .expect("read prompt")
                .as_deref(),
            Some("make the sky green")
        );
    }

    /// The model allowlist would have refused every character class in
    /// here. A prompt is free-form human writing, not an identifier, so
    /// it has to come back exactly as it was sent.
    #[test]
    fn a_multipart_prompt_keeps_spaces_punctuation_newlines_and_non_ascii() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nRemove the cat, then add a dog.\nMake it étudiant-friendly!\r\n--b--\r\n";
        assert_eq!(
            multipart_prompt(body.as_bytes(), "multipart/form-data; boundary=b")
                .expect("read prompt")
                .as_deref(),
            Some("Remove the cat, then add a dog.\nMake it étudiant-friendly!")
        );
    }

    /// A plain transcription carries no prompt, so its absence is the
    /// ordinary case and must not read as a refusal.
    #[test]
    fn multipart_without_a_prompt_field_is_not_an_error() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.bin\"\r\n\r\naudio\r\n--b--\r\n";
        assert_eq!(
            multipart_prompt(body, "multipart/form-data; boundary=b").expect("no prompt is fine"),
            None
        );
    }

    #[test]
    fn an_oversized_multipart_prompt_is_truncated_rather_than_refused() {
        let prompt = "a".repeat(MULTIPART_PROMPT_MAX_BYTES + 512);
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{prompt}\r\n--b--\r\n"
        );
        let read = multipart_prompt(body.as_bytes(), "multipart/form-data; boundary=b")
            .expect("an oversized prompt is capped, not rejected")
            .expect("the prompt part is present");

        assert_eq!(read.len(), MULTIPART_PROMPT_MAX_BYTES);
        assert!(read.bytes().all(|byte| byte == b'a'));
    }

    /// Bytes that are not UTF-8 give the classifier replacement
    /// characters to read. Erroring instead would make one bad byte a
    /// way to skip the scan.
    #[test]
    fn invalid_utf8_in_a_multipart_prompt_is_decoded_lossily() {
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nbad \xff\r\n--b--\r\n";
        assert_eq!(
            multipart_prompt(body, "multipart/form-data; boundary=b")
                .expect("lossy decode")
                .as_deref(),
            Some("bad \u{fffd}")
        );
    }

    #[test]
    fn a_duplicate_multipart_prompt_is_refused_like_a_duplicate_model() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nfirst\r\n--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nsecond\r\n--b--\r\n";
        let error = multipart_prompt(body, "multipart/form-data; boundary=b")
            .expect_err("two prompt parts leave the scanned text ambiguous");

        assert!(matches!(error, ModelPlaneError::InvalidRequest));
    }

    /// Both readers share one boundary walk, so the guard against them
    /// picking up each other's part is worth pinning in both part
    /// orders.
    #[test]
    fn the_shared_walker_keeps_model_and_prompt_apart() {
        let model_first = b"--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\npublic/dall-e\r\n--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\npublic/dall-e is not the prompt\r\n--b--\r\n";
        let prompt_first = b"--b\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\npublic/dall-e is not the prompt\r\n--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\npublic/dall-e\r\n--b--\r\n";

        for body in [model_first.as_slice(), prompt_first.as_slice()] {
            assert_eq!(
                multipart_model(body, "multipart/form-data; boundary=b")
                    .expect("read model")
                    .as_deref(),
                Some("public/dall-e")
            );
            assert_eq!(
                multipart_prompt(body, "multipart/form-data; boundary=b")
                    .expect("read prompt")
                    .as_deref(),
                Some("public/dall-e is not the prompt")
            );
        }
    }
}
