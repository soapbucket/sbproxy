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
        multipart_model_range(body, boundary)?.ok_or(ModelPlaneError::InvalidRequest)?;
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
    let Some(range) = multipart_model_range(body, &boundary)? else {
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

fn multipart_model_range(
    body: &[u8],
    boundary: &[u8],
) -> Result<Option<std::ops::Range<usize>>, ModelPlaneError> {
    let mut delimiter = Vec::with_capacity(boundary.len() + 2);
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(boundary);
    let mut next_delimiter = Vec::with_capacity(boundary.len() + 4);
    next_delimiter.extend_from_slice(b"\r\n");
    next_delimiter.extend_from_slice(&delimiter);

    let mut cursor = 0usize;
    let mut model_range = None;
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
        if multipart_field_name(headers).as_deref() == Some("model")
            && model_range.replace(part_start..part_end).is_some()
        {
            return Err(ModelPlaneError::InvalidRequest);
        }
        cursor = part_end + 2;
    }
    if !saw_closing {
        return Err(ModelPlaneError::InvalidRequest);
    }
    Ok(model_range)
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
}
