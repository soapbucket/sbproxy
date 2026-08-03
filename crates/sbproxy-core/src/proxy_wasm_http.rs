use std::fmt;

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Method, Uri};
use pingora_http::{RequestHeader, ResponseHeader};
use sbproxy_config::{BundleBodyMode, FailureMode, ProxyWasmFilterAttachment};
use sbproxy_extension::bundle::{
    build_proxy_wasm_filter, BundleRegistry, ProxyWasmAction, ProxyWasmCallFailure,
    ProxyWasmFilter, ProxyWasmLocalResponse, ProxyWasmSession,
};

pub(crate) struct ProxyWasmFilterChain {
    filters: Vec<CompiledProxyWasmFilter>,
    streams_bodies: bool,
    max_buffer_bytes: usize,
}

struct CompiledProxyWasmFilter {
    filter: ProxyWasmFilter,
    failure_posture: FailureMode,
}

struct LiveProxyWasmFilter {
    type_name: String,
    session: ProxyWasmSession,
    failure_posture: FailureMode,
    body_mode: BundleBodyMode,
    max_input_bytes: usize,
    request_body_enabled: bool,
    response_body_enabled: bool,
    active: bool,
    finalized: bool,
}

pub(crate) struct ProxyWasmHttpState {
    filters: Vec<LiveProxyWasmFilter>,
    streams_bodies: bool,
    max_buffer_bytes: usize,
    request_buffer_limit: usize,
    response_buffer_limit: usize,
    request_buffer: BytesMut,
    response_buffer: BytesMut,
    request_body_bypass: bool,
    response_body_bypass: bool,
    pending_local_response: Option<ProxyWasmLocalResponse>,
    response_stream_failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyWasmHttpFailure {
    filter_type: String,
    code: &'static str,
}

impl ProxyWasmHttpFailure {
    fn new(filter_type: impl Into<String>, code: &'static str) -> Self {
        Self {
            filter_type: filter_type.into(),
            code,
        }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ProxyWasmHttpFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Proxy-Wasm filter `{}` failed: {}",
            self.filter_type, self.code
        )
    }
}

impl std::error::Error for ProxyWasmHttpFailure {}

impl ProxyWasmFilterChain {
    pub(crate) fn compile(
        origin_id: &str,
        attachments: &[ProxyWasmFilterAttachment],
        registry: &dyn BundleRegistry,
    ) -> anyhow::Result<Self> {
        let mut filters = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let hook = registry
                .proxy_wasm_filter(&attachment.type_name)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "origin `{origin_id}`: Proxy-Wasm filter `{}` is not installed",
                        attachment.type_name
                    )
                })?;
            hook.validate_config(&attachment.config).with_context(|| {
                format!(
                    "origin `{origin_id}`: invalid config for Proxy-Wasm filter `{}`",
                    attachment.type_name
                )
            })?;
            let filter =
                build_proxy_wasm_filter(hook, attachment.config.clone()).with_context(|| {
                    format!(
                        "origin `{origin_id}`: could not build Proxy-Wasm filter `{}`",
                        attachment.type_name
                    )
                })?;
            let failure_posture = attachment
                .failure_posture
                .unwrap_or(hook.manifest().failure_posture);

            let mut preflight = filter.start_session().map_err(|failure| {
                anyhow::anyhow!(
                    "origin `{origin_id}`: Proxy-Wasm filter `{}` rejected candidate configuration: {}",
                    attachment.type_name,
                    failure.code()
                )
            })?;
            preflight.finish().map_err(|failure| {
                anyhow::anyhow!(
                    "origin `{origin_id}`: Proxy-Wasm filter `{}` failed candidate preflight: {}",
                    attachment.type_name,
                    failure.code()
                )
            })?;
            if !preflight.is_finished() {
                anyhow::bail!(
                    "origin `{origin_id}`: Proxy-Wasm filter `{}` did not finish candidate preflight",
                    attachment.type_name
                );
            }
            filters.push(CompiledProxyWasmFilter {
                filter,
                failure_posture,
            });
        }

        let streams_bodies = filters
            .iter()
            .all(|compiled| compiled.filter.body_mode() != BundleBodyMode::Buffered);
        let max_buffer_bytes = filters
            .iter()
            .filter(|compiled| compiled.filter.body_mode() != BundleBodyMode::None)
            .map(|compiled| compiled.filter.max_input_bytes())
            .min()
            .unwrap_or(0);
        Ok(Self {
            filters,
            streams_bodies,
            max_buffer_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) const fn streams_bodies(&self) -> bool {
        self.streams_bodies
    }

    pub(crate) fn start(&self) -> Result<ProxyWasmHttpState, ProxyWasmHttpFailure> {
        self.start_with(ProxyWasmFilter::start_session, |type_name, session| {
            finish_session(type_name, session)
        })
    }

    fn start_with<Start, Finish>(
        &self,
        mut start: Start,
        mut finish: Finish,
    ) -> Result<ProxyWasmHttpState, ProxyWasmHttpFailure>
    where
        Start: FnMut(&ProxyWasmFilter) -> Result<ProxyWasmSession, ProxyWasmCallFailure>,
        Finish: FnMut(&str, &mut ProxyWasmSession),
    {
        let mut filters: Vec<LiveProxyWasmFilter> = Vec::with_capacity(self.filters.len());
        for compiled in &self.filters {
            let type_name = compiled.filter.type_name().to_owned();
            let session = match start(&compiled.filter) {
                Ok(session) => session,
                Err(failure) if compiled.failure_posture.admits() => {
                    tracing::warn!(
                        filter_type = %type_name,
                        failure_code = failure.code(),
                        failure_posture = ?compiled.failure_posture,
                        "Proxy-Wasm filter session failed to start; admitting request"
                    );
                    continue;
                }
                Err(failure) => {
                    for live in filters.iter_mut().rev() {
                        finish(&live.type_name, &mut live.session);
                    }
                    return Err(ProxyWasmHttpFailure::new(type_name, failure.code()));
                }
            };
            filters.push(LiveProxyWasmFilter {
                type_name,
                session,
                failure_posture: compiled.failure_posture,
                body_mode: compiled.filter.body_mode(),
                max_input_bytes: compiled.filter.max_input_bytes(),
                request_body_enabled: compiled.filter.body_mode() != BundleBodyMode::None,
                response_body_enabled: compiled.filter.body_mode() != BundleBodyMode::None,
                active: true,
                finalized: false,
            });
        }

        let (streams_bodies, max_buffer_bytes) = if filters.len() == self.filters.len() {
            (self.streams_bodies, self.max_buffer_bytes)
        } else {
            (
                filters
                    .iter()
                    .all(|filter| filter.body_mode != BundleBodyMode::Buffered),
                filters
                    .iter()
                    .filter(|filter| filter.body_mode != BundleBodyMode::None)
                    .map(|filter| filter.max_input_bytes)
                    .min()
                    .unwrap_or(0),
            )
        };
        Ok(ProxyWasmHttpState {
            filters,
            streams_bodies,
            max_buffer_bytes,
            request_buffer_limit: max_buffer_bytes,
            response_buffer_limit: max_buffer_bytes,
            request_buffer: BytesMut::new(),
            response_buffer: BytesMut::new(),
            request_body_bypass: false,
            response_body_bypass: false,
            pending_local_response: None,
            response_stream_failed: false,
        })
    }
}

fn finish_session(type_name: &str, session: &mut ProxyWasmSession) {
    if let Err(failure) = session.finish() {
        tracing::warn!(
            filter_type = type_name,
            failure_code = failure.code(),
            "Proxy-Wasm filter session finalization failed"
        );
    } else if !session.is_finished() {
        tracing::warn!(
            filter_type = type_name,
            failure_code = "unresolved_pause",
            "Proxy-Wasm filter session did not finish"
        );
    }
}

impl ProxyWasmHttpState {
    pub(crate) fn filter_request_headers(
        &mut self,
        header: &mut RequestHeader,
        end_of_stream: bool,
    ) -> Result<(), ProxyWasmHttpFailure> {
        let (mut headers, opaque_headers) = request_header_map(header);
        for filter in &mut self.filters {
            if !filter.active {
                continue;
            }
            let before = headers.clone();
            let result = filter.session.on_request_headers(headers, end_of_stream);
            match result {
                Ok(result) => {
                    if let Some(local_response) = result.local_response {
                        self.pending_local_response = Some(local_response);
                        return Ok(());
                    }
                    match result.action {
                        ProxyWasmAction::Continue => {
                            let (accepted, deactivate) = accept_header_map(
                                &filter.type_name,
                                filter.failure_posture,
                                before,
                                result.headers,
                                validate_request_header_map,
                            )?;
                            headers = accepted;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                        ProxyWasmAction::Pause => {
                            let deactivate = handle_filter_failure(
                                &filter.type_name,
                                filter.failure_posture,
                                "unresolved_pause",
                            )?;
                            headers = before;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                        ProxyWasmAction::Close => {
                            let deactivate = handle_filter_failure(
                                &filter.type_name,
                                filter.failure_posture,
                                "closed_without_response",
                            )?;
                            headers = before;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                    }
                }
                Err(failure) => {
                    let deactivate = handle_filter_failure(
                        &filter.type_name,
                        filter.failure_posture,
                        failure.code(),
                    )?;
                    headers = before;
                    if deactivate {
                        deactivate_filter(filter);
                    }
                }
            }
        }
        apply_request_header_map(header, &headers, &opaque_headers)
    }

    pub(crate) fn filter_response_headers(
        &mut self,
        header: &mut ResponseHeader,
        end_of_stream: bool,
    ) -> Result<(), ProxyWasmHttpFailure> {
        let (mut headers, opaque_headers) = response_header_map(header);
        for filter in &mut self.filters {
            if !filter.active {
                continue;
            }
            let before = headers.clone();
            let result = filter.session.on_response_headers(headers, end_of_stream);
            match result {
                Ok(result) => {
                    if let Some(local_response) = result.local_response {
                        self.pending_local_response = Some(local_response);
                        return Ok(());
                    }
                    match result.action {
                        ProxyWasmAction::Continue => {
                            let (accepted, deactivate) = accept_header_map(
                                &filter.type_name,
                                filter.failure_posture,
                                before,
                                result.headers,
                                validate_response_header_map,
                            )?;
                            headers = accepted;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                        ProxyWasmAction::Pause => {
                            let deactivate = handle_filter_failure(
                                &filter.type_name,
                                filter.failure_posture,
                                "unresolved_pause",
                            )?;
                            headers = before;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                        ProxyWasmAction::Close => {
                            let deactivate = handle_filter_failure(
                                &filter.type_name,
                                filter.failure_posture,
                                "closed_without_response",
                            )?;
                            headers = before;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                        }
                    }
                }
                Err(failure) => {
                    let deactivate = handle_filter_failure(
                        &filter.type_name,
                        filter.failure_posture,
                        failure.code(),
                    )?;
                    headers = before;
                    if deactivate {
                        deactivate_filter(filter);
                    }
                }
            }
        }
        apply_response_header_map(header, &headers, &opaque_headers)
    }

    pub(crate) fn take_pending_local_response(&mut self) -> Option<ProxyWasmLocalResponse> {
        self.pending_local_response.take()
    }

    fn set_internal_failure_response(&mut self) {
        self.pending_local_response = Some(internal_failure_response());
    }

    pub(crate) fn filter_request_body(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<(), ProxyWasmHttpFailure> {
        if self.request_body_bypass || self.max_buffer_bytes == 0 {
            return Ok(());
        }
        if self.streams_bodies {
            let input = body.take().unwrap_or_default();
            let (output, local_response) = run_body_filters(
                &mut self.filters,
                input,
                end_of_stream,
                BodyDirection::Request,
            )?;
            if let Some(local_response) = local_response {
                self.pending_local_response = Some(local_response);
                *body = None;
            } else {
                *body = Some(output);
            }
            return Ok(());
        }

        let input = body.take().unwrap_or_default();
        let next_size = self.request_buffer.len().saturating_add(input.len());
        if next_size > self.request_buffer_limit {
            let active =
                handle_buffer_limits(&mut self.filters, next_size, BodyDirection::Request)?;
            self.request_buffer_limit = next_body_limit(&self.filters, BodyDirection::Request);
            if !active {
                self.request_buffer.extend_from_slice(&input);
                *body = Some(self.request_buffer.split().freeze());
                self.request_body_bypass = true;
                return Ok(());
            }
        }
        self.request_buffer.extend_from_slice(&input);
        if !end_of_stream {
            *body = Some(Bytes::new());
            return Ok(());
        }

        let input = self.request_buffer.split().freeze();
        let (output, local_response) =
            run_body_filters(&mut self.filters, input, true, BodyDirection::Request)?;
        if let Some(local_response) = local_response {
            self.pending_local_response = Some(local_response);
            *body = None;
        } else {
            *body = Some(output);
        }
        Ok(())
    }

    pub(crate) fn filter_response_body(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<(), ProxyWasmHttpFailure> {
        if self.response_body_bypass || self.max_buffer_bytes == 0 {
            return Ok(());
        }
        if self.streams_bodies {
            let input = body.take().unwrap_or_default();
            let (output, local_response) = run_body_filters(
                &mut self.filters,
                input,
                end_of_stream,
                BodyDirection::Response,
            )?;
            if local_response.is_some() {
                return Err(ProxyWasmHttpFailure::new("host", "late_local_response"));
            }
            *body = Some(output);
            return Ok(());
        }

        let input = body.take().unwrap_or_default();
        let next_size = self.response_buffer.len().saturating_add(input.len());
        if next_size > self.response_buffer_limit {
            let active =
                handle_buffer_limits(&mut self.filters, next_size, BodyDirection::Response)?;
            self.response_buffer_limit = next_body_limit(&self.filters, BodyDirection::Response);
            if !active {
                self.response_buffer.extend_from_slice(&input);
                *body = Some(self.response_buffer.split().freeze());
                self.response_body_bypass = true;
                return Ok(());
            }
        }
        self.response_buffer.extend_from_slice(&input);
        if !end_of_stream {
            *body = Some(Bytes::new());
            return Ok(());
        }

        let input = self.response_buffer.split().freeze();
        let (output, local_response) =
            run_body_filters(&mut self.filters, input, true, BodyDirection::Response)?;
        if local_response.is_some() {
            return Err(ProxyWasmHttpFailure::new("host", "late_local_response"));
        }
        *body = Some(output);
        Ok(())
    }
}

fn internal_failure_response() -> ProxyWasmLocalResponse {
    ProxyWasmLocalResponse {
        status: 500,
        grpc_status: None,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: Bytes::from_static(b"Proxy-Wasm filter failed"),
    }
}

#[derive(Clone, Copy)]
enum BodyDirection {
    Request,
    Response,
}

fn run_body_filters(
    filters: &mut [LiveProxyWasmFilter],
    mut body: Bytes,
    end_of_stream: bool,
    direction: BodyDirection,
) -> Result<(Bytes, Option<ProxyWasmLocalResponse>), ProxyWasmHttpFailure> {
    for filter in filters {
        let enabled = match direction {
            BodyDirection::Request => filter.request_body_enabled,
            BodyDirection::Response => filter.response_body_enabled,
        };
        if !filter.active || !enabled {
            continue;
        }
        let before = body.clone();
        let result = match direction {
            BodyDirection::Request => filter.session.on_request_body(body, end_of_stream),
            BodyDirection::Response => filter.session.on_response_body(body, end_of_stream),
        };
        match result {
            Ok(result) => {
                if let Some(local_response) = result.local_response {
                    match direction {
                        BodyDirection::Request => {
                            return Ok((Bytes::new(), Some(local_response)));
                        }
                        BodyDirection::Response => {
                            let deactivate = handle_filter_failure(
                                &filter.type_name,
                                filter.failure_posture,
                                "late_local_response",
                            )?;
                            body = before;
                            if deactivate {
                                deactivate_filter(filter);
                            }
                            continue;
                        }
                    }
                }
                match result.action {
                    ProxyWasmAction::Continue => body = result.body,
                    ProxyWasmAction::Pause => {
                        let deactivate = handle_filter_failure(
                            &filter.type_name,
                            filter.failure_posture,
                            "unresolved_pause",
                        )?;
                        body = before;
                        if deactivate {
                            deactivate_filter(filter);
                        }
                    }
                    ProxyWasmAction::Close => {
                        let deactivate = handle_filter_failure(
                            &filter.type_name,
                            filter.failure_posture,
                            "closed_without_response",
                        )?;
                        body = before;
                        if deactivate {
                            deactivate_filter(filter);
                        }
                    }
                }
            }
            Err(failure) => {
                let deactivate = handle_filter_failure(
                    &filter.type_name,
                    filter.failure_posture,
                    failure.code(),
                )?;
                body = before;
                if deactivate {
                    deactivate_filter(filter);
                }
            }
        }
    }
    Ok((body, None))
}

fn handle_buffer_limits(
    filters: &mut [LiveProxyWasmFilter],
    body_size: usize,
    direction: BodyDirection,
) -> Result<bool, ProxyWasmHttpFailure> {
    for filter in filters.iter_mut() {
        let enabled = match direction {
            BodyDirection::Request => &mut filter.request_body_enabled,
            BodyDirection::Response => &mut filter.response_body_enabled,
        };
        if filter.active && *enabled && body_size > filter.max_input_bytes {
            let _ =
                handle_filter_failure(&filter.type_name, filter.failure_posture, "input_limit")?;
            *enabled = false;
        }
    }
    Ok(filters.iter().any(|filter| match direction {
        BodyDirection::Request => filter.active && filter.request_body_enabled,
        BodyDirection::Response => filter.active && filter.response_body_enabled,
    }))
}

fn next_body_limit(filters: &[LiveProxyWasmFilter], direction: BodyDirection) -> usize {
    filters
        .iter()
        .filter(|filter| match direction {
            BodyDirection::Request => filter.active && filter.request_body_enabled,
            BodyDirection::Response => filter.active && filter.response_body_enabled,
        })
        .map(|filter| filter.max_input_bytes)
        .min()
        .unwrap_or(0)
}

type HeaderMapValidator = fn(&[(String, String)]) -> Result<(), &'static str>;

fn accept_header_map(
    filter_type: &str,
    failure_posture: FailureMode,
    before: Vec<(String, String)>,
    candidate: Vec<(String, String)>,
    validate: HeaderMapValidator,
) -> Result<(Vec<(String, String)>, bool), ProxyWasmHttpFailure> {
    match validate(&candidate) {
        Ok(()) => Ok((candidate, false)),
        Err(code) => {
            let deactivate = handle_filter_failure(filter_type, failure_posture, code)?;
            Ok((before, deactivate))
        }
    }
}

fn handle_filter_failure(
    filter_type: &str,
    failure_posture: FailureMode,
    code: &'static str,
) -> Result<bool, ProxyWasmHttpFailure> {
    if failure_posture.admits() {
        tracing::warn!(
            filter_type,
            failure_code = code,
            ?failure_posture,
            "Proxy-Wasm filter callback failed; admitting request"
        );
        Ok(true)
    } else {
        Err(ProxyWasmHttpFailure::new(filter_type, code))
    }
}

fn deactivate_filter(filter: &mut LiveProxyWasmFilter) {
    if !filter.active {
        return;
    }
    filter.active = false;
    finish_session(&filter.type_name, &mut filter.session);
    filter.finalized = true;
}

type OpaqueHeaders = Vec<(HeaderName, HeaderValue)>;

fn request_header_map(header: &RequestHeader) -> (Vec<(String, String)>, OpaqueHeaders) {
    let mut output = Vec::with_capacity(header.headers.len() + 3);
    let mut opaque = Vec::new();
    output.push((":method".to_string(), header.method.as_str().to_string()));
    output.push((":path".to_string(), header.uri.to_string()));
    let authority = header
        .uri
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| {
            header
                .headers
                .get("host")
                .and_then(|value| value.to_str().ok())
        });
    if let Some(authority) = authority {
        output.push((":authority".to_string(), authority.to_string()));
    }
    if let Some(scheme) = header.uri.scheme_str() {
        output.push((":scheme".to_string(), scheme.to_string()));
    }
    for (name, value) in &header.headers {
        if name == http::header::HOST {
            continue;
        }
        match value.to_str() {
            Ok(value) => output.push((name.as_str().to_string(), value.to_string())),
            Err(_) => opaque.push((name.clone(), value.clone())),
        }
    }
    (output, opaque)
}

fn response_header_map(header: &ResponseHeader) -> (Vec<(String, String)>, OpaqueHeaders) {
    let mut output = Vec::with_capacity(header.headers.len() + 1);
    let mut opaque = Vec::new();
    output.push((":status".to_string(), header.status.as_u16().to_string()));
    for (name, value) in &header.headers {
        match value.to_str() {
            Ok(value) => output.push((name.as_str().to_string(), value.to_string())),
            Err(_) => opaque.push((name.clone(), value.clone())),
        }
    }
    (output, opaque)
}

fn validate_request_header_map(headers: &[(String, String)]) -> Result<(), &'static str> {
    let mut method_seen = false;
    let mut path_seen = false;
    let mut authority_seen = false;
    let mut scheme_seen = false;
    for (name, value) in headers {
        match name.as_str() {
            ":method" if !method_seen => {
                method_seen = true;
                Method::from_bytes(value.as_bytes()).map_err(|_| "invalid_request_method")?;
            }
            ":path" if !path_seen => {
                path_seen = true;
                Uri::try_from(value.as_str()).map_err(|_| "invalid_request_path")?;
            }
            ":authority" if !authority_seen => {
                authority_seen = true;
                HeaderValue::from_str(value).map_err(|_| "invalid_request_authority")?;
            }
            ":scheme" if !scheme_seen => {
                scheme_seen = true;
                if !matches!(value.as_str(), "http" | "https") {
                    return Err("invalid_request_scheme");
                }
            }
            name if name.starts_with(':') => return Err("invalid_request_pseudo_header"),
            _ => {
                parse_header(name, value).map_err(|failure| failure.code())?;
            }
        }
    }
    Ok(())
}

fn validate_response_header_map(headers: &[(String, String)]) -> Result<(), &'static str> {
    let mut status_seen = false;
    for (name, value) in headers {
        match name.as_str() {
            ":status" if !status_seen => {
                status_seen = true;
                let value = value
                    .parse::<u16>()
                    .map_err(|_| "invalid_response_status")?;
                http::StatusCode::from_u16(value).map_err(|_| "invalid_response_status")?;
            }
            name if name.starts_with(':') => return Err("invalid_response_pseudo_header"),
            _ => {
                parse_header(name, value).map_err(|failure| failure.code())?;
            }
        }
    }
    Ok(())
}

fn apply_request_header_map(
    header: &mut RequestHeader,
    headers: &[(String, String)],
    opaque_headers: &[(HeaderName, HeaderValue)],
) -> Result<(), ProxyWasmHttpFailure> {
    let mut method = header.method.clone();
    let mut uri = header.uri.clone();
    let mut authority = header.uri.authority().map(ToString::to_string).or_else(|| {
        header
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
    });
    let mut ordinary = Vec::new();
    for (name, value) in headers {
        match name.as_str() {
            ":method" => {
                method = Method::from_bytes(value.as_bytes())
                    .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_request_method"))?;
            }
            ":path" => {
                uri = Uri::try_from(value.as_str())
                    .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_request_path"))?;
            }
            ":authority" => authority = Some(value.clone()),
            ":scheme" => {
                if !matches!(value.as_str(), "http" | "https") {
                    return Err(ProxyWasmHttpFailure::new("host", "invalid_request_scheme"));
                }
            }
            name if name.starts_with(':') => {
                return Err(ProxyWasmHttpFailure::new(
                    "host",
                    "unknown_request_pseudo_header",
                ));
            }
            _ => ordinary.push(parse_header(name, value)?),
        }
    }

    clear_request_headers(header);
    header.set_method(method);
    header.set_uri(uri);
    if let Some(authority) = authority {
        header
            .append_header(http::header::HOST, authority)
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_request_authority"))?;
    }
    for (name, value) in ordinary {
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        header
            .append_header(name, value)
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_request_header"))?;
    }
    for (name, value) in opaque_headers {
        header
            .append_header(name.clone(), value.clone())
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_request_header"))?;
    }
    Ok(())
}

fn apply_response_header_map(
    header: &mut ResponseHeader,
    headers: &[(String, String)],
    opaque_headers: &[(HeaderName, HeaderValue)],
) -> Result<(), ProxyWasmHttpFailure> {
    let mut status = header.status;
    let mut ordinary = Vec::new();
    for (name, value) in headers {
        match name.as_str() {
            ":status" => {
                let value = value
                    .parse::<u16>()
                    .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_response_status"))?;
                status = http::StatusCode::from_u16(value)
                    .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_response_status"))?;
            }
            name if name.starts_with(':') => {
                return Err(ProxyWasmHttpFailure::new(
                    "host",
                    "unknown_response_pseudo_header",
                ));
            }
            _ => ordinary.push(parse_header(name, value)?),
        }
    }

    clear_response_headers(header);
    header
        .set_status(status)
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_response_status"))?;
    for (name, value) in ordinary {
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        header
            .append_header(name, value)
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_response_header"))?;
    }
    for (name, value) in opaque_headers {
        header
            .append_header(name.clone(), value.clone())
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_response_header"))?;
    }
    Ok(())
}

pub(crate) fn apply_local_response_header(
    header: &mut ResponseHeader,
    local_response: &ProxyWasmLocalResponse,
) -> Result<(), ProxyWasmHttpFailure> {
    clear_response_headers(header);
    header
        .set_status(local_response.status)
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_local_response_status"))?;
    for (name, value) in &local_response.headers {
        let (name, value) = parse_header(name, value)?;
        if is_hop_by_hop_header(&name)
            || name == http::header::CONTENT_LENGTH
            || (local_response.grpc_status.is_some() && name.as_str() == "grpc-status")
        {
            continue;
        }
        header
            .append_header(name, value)
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_local_response_header"))?;
    }
    if let Some(grpc_status) = local_response.grpc_status {
        header
            .insert_header("grpc-status", grpc_status.to_string())
            .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_grpc_status"))?;
    }
    header
        .insert_header(
            http::header::CONTENT_LENGTH,
            local_response.body.len().to_string(),
        )
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_local_content_length"))?;
    Ok(())
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn parse_header(
    name: &str,
    value: &str,
) -> Result<(HeaderName, HeaderValue), ProxyWasmHttpFailure> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_header_name"))?;
    let value = HeaderValue::from_str(value)
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_header_value"))?;
    Ok((name, value))
}

fn clear_request_headers(header: &mut RequestHeader) {
    let names = header.headers.keys().cloned().collect::<Vec<_>>();
    for name in names {
        header.remove_header(&name);
    }
}

fn clear_response_headers(header: &mut ResponseHeader) {
    let names = header.headers.keys().cloned().collect::<Vec<_>>();
    for name in names {
        header.remove_header(&name);
    }
}

pub(crate) async fn start_request(
    session: &mut pingora_proxy::Session,
    ctx: &mut crate::context::RequestContext,
    origin_idx: usize,
) -> pingora_error::Result<bool> {
    let pipeline = ctx.pipeline.clone();
    let Some(chain) = pipeline
        .proxy_wasm_filters
        .get(origin_idx)
        .and_then(Option::as_ref)
    else {
        return Ok(false);
    };
    let mut state = match chain.start() {
        Ok(state) => state,
        Err(failure) => {
            trace_filter_failure("request_start", &failure);
            let local_response = internal_failure_response();
            send_local_response(session, &local_response).await?;
            ctx.response_status = Some(local_response.status);
            return Ok(true);
        }
    };
    let end_of_stream = session.as_mut().is_body_empty();
    if let Err(failure) = state.filter_request_headers(session.req_header_mut(), end_of_stream) {
        trace_filter_failure("request_headers", &failure);
        state.finish();
        let local_response = internal_failure_response();
        send_local_response(session, &local_response).await?;
        ctx.response_status = Some(local_response.status);
        return Ok(true);
    }
    if let Some(local_response) = state.take_pending_local_response() {
        state.finish();
        send_local_response(session, &local_response).await?;
        ctx.response_status = Some(local_response.status);
        return Ok(true);
    }
    ctx.proxy_wasm = Some(parking_lot::Mutex::new(state));
    Ok(false)
}

pub(crate) fn filter_response_headers(
    session: &pingora_proxy::Session,
    header: &mut ResponseHeader,
    ctx: &mut crate::context::RequestContext,
) -> pingora_error::Result<()> {
    let Some(state) = ctx.proxy_wasm.as_ref() else {
        return Ok(());
    };
    let end_of_stream = response_has_no_body(session, header);
    let mut state = state.lock();
    if let Err(failure) = state.filter_response_headers(header, end_of_stream) {
        trace_filter_failure("response_headers", &failure);
        state.set_internal_failure_response();
        return Err(pingora_filter_error(&failure));
    }
    if let Some(status) = state
        .pending_local_response
        .as_ref()
        .map(|response| response.status)
    {
        return Err(pingora_error::Error::explain(
            pingora_error::ErrorType::HTTPStatus(status),
            "proxy_wasm:local_response",
        ));
    }
    Ok(())
}

pub(crate) fn filter_request_body(
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut crate::context::RequestContext,
) -> pingora_error::Result<()> {
    let Some(state) = ctx.proxy_wasm.as_ref() else {
        return Ok(());
    };
    let mut state = state.lock();
    if let Err(failure) = state.filter_request_body(body, end_of_stream) {
        trace_filter_failure("request_body", &failure);
        state.set_internal_failure_response();
        return Err(pingora_filter_error(&failure));
    }
    if let Some(status) = state
        .pending_local_response
        .as_ref()
        .map(|response| response.status)
    {
        return Err(pingora_error::Error::explain(
            pingora_error::ErrorType::HTTPStatus(status),
            "proxy_wasm:local_response",
        ));
    }
    Ok(())
}

pub(crate) fn filter_response_body(
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut crate::context::RequestContext,
) -> pingora_error::Result<()> {
    let Some(state) = ctx.proxy_wasm.as_ref() else {
        return Ok(());
    };
    let mut state = state.lock();
    match state.filter_response_body(body, end_of_stream) {
        Ok(()) => Ok(()),
        Err(failure) => {
            state.response_stream_failed = true;
            trace_filter_failure("response_body", &failure);
            Err(pingora_filter_error(&failure))
        }
    }
}

pub(crate) fn take_pending_local_response(
    ctx: &mut crate::context::RequestContext,
) -> Option<ProxyWasmLocalResponse> {
    ctx.proxy_wasm
        .as_ref()
        .and_then(|state| state.lock().take_pending_local_response())
}

pub(crate) fn has_pending_local_response(ctx: &crate::context::RequestContext) -> bool {
    ctx.proxy_wasm
        .as_ref()
        .is_some_and(|state| state.lock().pending_local_response.is_some())
}

pub(crate) fn response_stream_failed(ctx: &crate::context::RequestContext) -> bool {
    ctx.proxy_wasm
        .as_ref()
        .is_some_and(|state| state.lock().response_stream_failed)
}

pub(crate) fn finish(ctx: &mut crate::context::RequestContext) {
    let Some(state) = ctx.proxy_wasm.take() else {
        return;
    };
    state.into_inner().finish();
}

pub(crate) async fn send_local_response(
    session: &mut pingora_proxy::Session,
    local_response: &ProxyWasmLocalResponse,
) -> pingora_error::Result<()> {
    write_local_response(session, local_response).await
}

pub(crate) async fn send_terminal_local_response(
    session: &mut pingora_proxy::Session,
    local_response: &ProxyWasmLocalResponse,
) -> pingora_error::Result<()> {
    if terminal_local_response_closes_downstream(session.req_header().version) {
        session.set_keepalive(None);
    }
    write_local_response(session, local_response).await
}

async fn write_local_response(
    session: &mut pingora_proxy::Session,
    local_response: &ProxyWasmLocalResponse,
) -> pingora_error::Result<()> {
    let header =
        local_response_header(local_response).map_err(|failure| pingora_filter_error(&failure))?;
    let body_is_empty = local_response.body.is_empty();
    session
        .write_response_header(Box::new(header), body_is_empty)
        .await?;
    if !body_is_empty {
        session
            .write_response_body(Some(local_response.body.clone()), true)
            .await?;
    }
    Ok(())
}

fn local_response_header(
    local_response: &ProxyWasmLocalResponse,
) -> Result<ResponseHeader, ProxyWasmHttpFailure> {
    let mut header = ResponseHeader::build(local_response.status, None)
        .map_err(|_| ProxyWasmHttpFailure::new("host", "invalid_local_status"))?;
    apply_local_response_header(&mut header, local_response)?;
    Ok(header)
}

fn terminal_local_response_closes_downstream(version: http::Version) -> bool {
    matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
}

impl ProxyWasmHttpState {
    fn finish(&mut self) {
        for filter in &mut self.filters {
            if !filter.finalized {
                finish_session(&filter.type_name, &mut filter.session);
                filter.finalized = true;
            }
        }
    }
}

fn response_has_no_body(session: &pingora_proxy::Session, header: &ResponseHeader) -> bool {
    session.req_header().method == http::Method::HEAD
        || header.status.is_informational()
        || matches!(header.status.as_u16(), 204 | 304)
        || header
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            == Some(0)
}

fn trace_filter_failure(phase: &'static str, failure: &ProxyWasmHttpFailure) {
    tracing::warn!(
        phase,
        filter_type = %failure.filter_type,
        failure_code = failure.code,
        "Proxy-Wasm HTTP filter failed"
    );
}

fn pingora_filter_error(failure: &ProxyWasmHttpFailure) -> pingora_error::BError {
    pingora_error::Error::explain(
        pingora_error::ErrorType::HTTPStatus(500),
        format!("proxy_wasm:{}", failure.code),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use sbproxy_config::FailureMode;
    use sbproxy_plugin::ExtensionState;
    use tempfile::TempDir;

    use crate::pipeline::CompiledPipeline;

    const FILTER_WASM: &[u8] =
        include_bytes!("../../sbproxy-extension/src/bundle/testdata/proxy_wasm/http.wasm");
    const DEFERRED_DONE_WASM: &[u8] =
        include_bytes!("../../sbproxy-extension/src/bundle/testdata/proxy_wasm/deferred-done.wasm");
    const LATE_RESPONSE_WASM: &[u8] =
        include_bytes!("../../sbproxy-extension/src/bundle/testdata/proxy_wasm/late-response.wasm");

    fn write_bundle(root: &Path, hooks: &[(&str, &str)]) {
        write_bundle_with_wasm(root, hooks, FILTER_WASM);
    }

    fn write_bundle_with_wasm(root: &Path, hooks: &[(&str, &str)], wasm: &[u8]) {
        let bundle = root.join("bundles/http-filter");
        std::fs::create_dir_all(&bundle).expect("create Proxy-Wasm bundle directory");
        std::fs::write(bundle.join("filter.wasm"), wasm).expect("write Proxy-Wasm fixture");
        let hooks = hooks
            .iter()
            .map(|(type_name, body_mode)| {
                format!(
                    "  - kind: proxy_wasm\n    type: {type_name}\n    execution:\n      body_mode: {body_mode}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let manifest = format!(
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: http-filter
version: 1.0.0
runtime: proxy_wasm
abi: 0.2.1
entry: filter.wasm
hooks:
{hooks}
"#
        );
        std::fs::write(bundle.join("bundle.yaml"), manifest).expect("write Proxy-Wasm manifest");
    }

    fn compile_config(filter_types: &[&str]) -> sbproxy_config::CompiledConfig {
        let attachments = filter_types
            .iter()
            .map(|type_name| {
                format!(
                    "      - type: {type_name}\n        config:\n          enabled: true\n        failure_posture: closed"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        sbproxy_config::compile_config(&format!(
            r#"extensions:
  bundles_dir: bundles
origins:
  filter.example:
    action:
      type: proxy
      url: http://127.0.0.1:18080
    filters:
{attachments}
proxy: {{}}
"#
        ))
        .expect("compile attachment config")
    }

    fn start_state(posture: FailureMode) -> super::ProxyWasmHttpState {
        start_state_with_mode(posture, "streamed")
    }

    fn start_state_with_mode(posture: FailureMode, body_mode: &str) -> super::ProxyWasmHttpState {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("fixture_filter", body_mode)]);
        let mut config = compile_config(&["fixture_filter"]);
        config.origins[0].filters[0].failure_posture = Some(posture);
        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("compile Proxy-Wasm fixture chain");
        pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain")
            .start()
            .expect("start Proxy-Wasm state")
    }

    #[test]
    fn pipeline_streams_when_every_proxy_wasm_filter_streams() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("streamed_filter", "streamed")]);

        let pipeline = CompiledPipeline::from_config_at(
            compile_config(&["streamed_filter"]),
            directory.path(),
        )
        .expect("compile streamed Proxy-Wasm chain");

        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        assert!(chain.streams_bodies());
    }

    #[test]
    fn pipeline_inventory_marks_an_attached_proxy_wasm_filter_active() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("fixture_filter", "streamed")]);

        let pipeline =
            CompiledPipeline::from_config_at(compile_config(&["fixture_filter"]), directory.path())
                .expect("compile attached Proxy-Wasm filter");
        let hook = pipeline
            .extension_inventory()
            .hooks
            .iter()
            .find(|hook| hook.match_key == "fixture_filter")
            .expect("attached filter inventory record");

        assert_eq!(hook.state, ExtensionState::Active);
        assert_eq!(hook.position, Some(0));
        assert_eq!(pipeline.extension_inventory().summary.active, 1);
    }

    #[test]
    fn pipeline_buffers_when_any_proxy_wasm_filter_buffers() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(
            directory.path(),
            &[
                ("streamed_filter", "streamed"),
                ("buffered_filter", "buffered"),
            ],
        );

        let pipeline = CompiledPipeline::from_config_at(
            compile_config(&["streamed_filter", "buffered_filter"]),
            directory.path(),
        )
        .expect("compile mixed Proxy-Wasm chain");

        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        assert!(!chain.streams_bodies());
    }

    #[test]
    fn pipeline_does_not_buffer_for_a_body_neutral_filter() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("headers_only_filter", "none")]);

        let pipeline = CompiledPipeline::from_config_at(
            compile_config(&["headers_only_filter"]),
            directory.path(),
        )
        .expect("compile header-only Proxy-Wasm chain");

        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        assert!(chain.streams_bodies());
        assert_eq!(chain.max_buffer_bytes, 0);
    }

    #[test]
    fn pipeline_streams_with_body_neutral_and_streamed_filters() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(
            directory.path(),
            &[
                ("headers_only_filter", "none"),
                ("streamed_filter", "streamed"),
            ],
        );

        let pipeline = CompiledPipeline::from_config_at(
            compile_config(&["headers_only_filter", "streamed_filter"]),
            directory.path(),
        )
        .expect("compile mixed header-only and streamed Proxy-Wasm chain");

        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        assert!(chain.streams_bodies());
        assert_ne!(chain.max_buffer_bytes, 0);
    }

    #[test]
    fn pipeline_rejects_an_unknown_proxy_wasm_filter_type() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("available_filter", "streamed")]);

        let error = match CompiledPipeline::from_config_at(
            compile_config(&["missing_filter"]),
            directory.path(),
        ) {
            Ok(_) => panic!("missing Proxy-Wasm type must reject the candidate"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("filter.example"), "{error}");
        assert!(error.contains("missing_filter"), "{error}");
    }

    #[test]
    fn pipeline_rejects_a_filter_that_cannot_finish_preflight() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("deferred_filter", "streamed")]);
        std::fs::write(
            directory.path().join("bundles/http-filter/filter.wasm"),
            DEFERRED_DONE_WASM,
        )
        .expect("replace fixture with deferred finalizer");

        let error = match CompiledPipeline::from_config_at(
            compile_config(&["deferred_filter"]),
            directory.path(),
        ) {
            Ok(_) => panic!("unfinished preflight must reject the candidate"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("filter.example"), "{error}");
        assert!(error.contains("deferred_filter"), "{error}");
        assert!(error.contains("finish candidate preflight"), "{error}");
    }

    #[test]
    fn pipeline_rejects_proxy_wasm_filters_on_non_proxy_actions() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("fixture_filter", "streamed")]);
        let config = sbproxy_config::compile_config(
            r#"extensions:
  bundles_dir: bundles
origins:
  filter.example:
    action: { type: echo }
    filters:
      - type: fixture_filter
        config: { enabled: true }
proxy: {}
"#,
        )
        .expect("compile attachment config");

        let error = match CompiledPipeline::from_config_at(config, directory.path()) {
            Ok(_) => panic!("non-proxy action must reject a Proxy-Wasm attachment"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("filter.example"), "{error}");
        assert!(error.contains("proxy action"), "{error}");
    }

    #[test]
    fn pipeline_rejects_proxy_wasm_filters_when_a_forward_rule_is_not_proxy() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("fixture_filter", "streamed")]);
        let config = sbproxy_config::compile_config(
            r#"extensions:
  bundles_dir: bundles
origins:
  filter.example:
    action:
      type: proxy
      url: http://127.0.0.1:18080
    filters:
      - type: fixture_filter
        config: { enabled: true }
    forward_rules:
      - rules:
          - path: { prefix: /local }
        origin:
          action: { type: echo }
proxy: {}
"#,
        )
        .expect("compile attachment config");

        let error = match CompiledPipeline::from_config_at(config, directory.path()) {
            Ok(_) => panic!("non-proxy forward action must reject a Proxy-Wasm attachment"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("filter.example"), "{error}");
        assert!(error.contains("forward rule"), "{error}");
        assert!(error.contains("proxy action"), "{error}");
    }

    #[test]
    fn pipeline_rejects_proxy_wasm_filters_with_a_direct_fallback_response() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(directory.path(), &[("fixture_filter", "streamed")]);
        let config = sbproxy_config::compile_config(
            r#"extensions:
  bundles_dir: bundles
origins:
  filter.example:
    action:
      type: proxy
      url: http://127.0.0.1:18080
    filters:
      - type: fixture_filter
        config: { enabled: true }
    fallback_origin:
      on_error: true
      origin:
        action:
          type: static
          status_code: 200
          body: fallback
proxy: {}
"#,
        )
        .expect("compile attachment config");

        let error = match CompiledPipeline::from_config_at(config, directory.path()) {
            Ok(_) => panic!("direct fallback must reject a Proxy-Wasm attachment"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("filter.example"), "{error}");
        assert!(error.contains("fallback_origin"), "{error}");
    }

    #[test]
    fn headers_apply_request_and_response_mutations() {
        let mut state = start_state(FailureMode::Closed);
        let mut request =
            pingora_http::RequestHeader::build("GET", b"/normal", Some(2)).expect("build request");
        request
            .append_header("host", "filter.example")
            .expect("set host");
        request
            .append_header("x-input", "request-value")
            .expect("set fixture input");

        state
            .filter_request_headers(&mut request, true)
            .expect("filter request headers");
        assert_eq!(
            request
                .headers
                .get("x-seen")
                .and_then(|value| value.to_str().ok()),
            Some("request-value")
        );

        let mut response =
            pingora_http::ResponseHeader::build(200, Some(1)).expect("build response");
        response
            .append_header("content-type", "text/plain")
            .expect("set response content type");
        state
            .filter_response_headers(&mut response, false)
            .expect("filter response headers");
        assert_eq!(
            response
                .headers
                .get("x-response")
                .and_then(|value| value.to_str().ok()),
            Some("filtered")
        );
    }

    #[test]
    fn headers_capture_guest_local_response() {
        let mut state = start_state(FailureMode::Closed);
        let mut request =
            pingora_http::RequestHeader::build("GET", b"/blocked", Some(2)).expect("build request");
        request
            .append_header("host", "filter.example")
            .expect("set host");
        request
            .append_header("x-block", "1")
            .expect("set block signal");

        state
            .filter_request_headers(&mut request, true)
            .expect("filter blocking request");
        let local = state
            .take_pending_local_response()
            .expect("guest local response");
        assert_eq!(local.status, 403);
        assert_eq!(&local.body[..], b"blocked");
    }

    #[test]
    fn headers_treat_unresolved_pause_by_failure_posture() {
        let mut closed = start_state(FailureMode::Closed);
        let mut closed_request = pingora_http::RequestHeader::build("GET", b"/paused", Some(2))
            .expect("build closed request");
        closed_request
            .append_header("host", "filter.example")
            .expect("set closed host");
        closed_request
            .append_header("x-pause", "1")
            .expect("set closed Pause signal");
        assert!(closed
            .filter_request_headers(&mut closed_request, true)
            .is_err());

        let mut open = start_state(FailureMode::Open);
        let mut open_request = pingora_http::RequestHeader::build("GET", b"/paused", Some(2))
            .expect("build open request");
        open_request
            .append_header("host", "filter.example")
            .expect("set open host");
        open_request
            .append_header("x-pause", "1")
            .expect("set open Pause signal");
        open.filter_request_headers(&mut open_request, true)
            .expect("open posture admits unresolved Pause");
        assert_eq!(
            open_request
                .headers
                .get("x-pause")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        assert!(!open.filters[0].active);
        assert!(open.filters[0].finalized);

        let mut later_response =
            pingora_http::ResponseHeader::build(200, None).expect("build later response");
        open.filter_response_headers(&mut later_response, true)
            .expect("deactivated filter is skipped in later phases");
        assert!(!later_response.headers.contains_key("x-response"));
    }

    #[test]
    fn closed_callback_failure_is_finalized_at_request_teardown() {
        let mut state = start_state(FailureMode::Closed);
        let mut request = pingora_http::RequestHeader::build("GET", b"/paused", Some(2))
            .expect("build closed request");
        request
            .append_header("host", "filter.example")
            .expect("set host");
        request
            .append_header("x-pause", "1")
            .expect("set Pause signal");

        state
            .filter_request_headers(&mut request, true)
            .expect_err("closed posture rejects unresolved Pause");
        assert!(!state.filters[0].finalized);

        state.finish();

        assert!(state.filters[0].finalized);
        assert!(state.filters[0].session.is_finished());
    }

    #[test]
    fn headers_apply_guest_conversion_failures_under_the_filter_posture() {
        let before = vec![(":status".to_string(), "200".to_string())];
        let invalid = vec![(":status".to_string(), "not-a-status".to_string())];

        let (admitted, deactivate) = super::accept_header_map(
            "fixture_filter",
            FailureMode::Open,
            before.clone(),
            invalid.clone(),
            super::validate_response_header_map,
        )
        .expect("open posture rolls back an invalid guest map");
        assert_eq!(admitted, before);
        assert!(deactivate);

        let failure = super::accept_header_map(
            "fixture_filter",
            FailureMode::Closed,
            before,
            invalid,
            super::validate_response_header_map,
        )
        .expect_err("closed posture rejects an invalid guest map");
        assert_eq!(failure.code(), "invalid_response_status");
    }

    #[test]
    fn headers_preserve_values_the_string_only_abi_cannot_represent() {
        let mut state = start_state(FailureMode::Closed);
        let mut request =
            pingora_http::RequestHeader::build("GET", b"/opaque", Some(3)).expect("build request");
        request
            .append_header("host", "filter.example")
            .expect("set host");
        request
            .append_header(
                "x-opaque",
                http::HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes"),
            )
            .expect("set opaque request header");

        state
            .filter_request_headers(&mut request, true)
            .expect("filter request with opaque header");

        assert_eq!(
            request
                .headers
                .get("x-opaque")
                .expect("preserved opaque header")
                .as_bytes(),
            &[0xff]
        );
    }

    #[test]
    fn body_streams_each_chunk_when_no_filter_requires_buffering() {
        let mut state = start_state(FailureMode::Closed);
        let mut request = Some(bytes::Bytes::from_static(b"request"));
        state
            .filter_request_body(&mut request, false)
            .expect("filter streamed request chunk");
        assert_eq!(request.as_deref(), Some(&b"request"[..]));

        let mut first_response = Some(bytes::Bytes::from_static(b"first"));
        state
            .filter_response_body(&mut first_response, false)
            .expect("filter first streamed response chunk");
        assert_eq!(first_response.as_deref(), Some(&b"filtered"[..]));

        let mut final_response = Some(bytes::Bytes::from_static(b"second"));
        state
            .filter_response_body(&mut final_response, true)
            .expect("filter final streamed response chunk");
        assert_eq!(final_response.as_deref(), Some(&b"filtered"[..]));
    }

    #[test]
    fn body_buffers_the_whole_stream_when_a_filter_requires_it() {
        let mut state = start_state_with_mode(FailureMode::Closed, "buffered");

        let mut first_request = Some(bytes::Bytes::from_static(b"req"));
        state
            .filter_request_body(&mut first_request, false)
            .expect("buffer first request chunk");
        assert_eq!(first_request.as_deref(), Some(&b""[..]));

        let mut final_request = Some(bytes::Bytes::from_static(b"uest"));
        state
            .filter_request_body(&mut final_request, true)
            .expect("emit buffered request");
        assert_eq!(final_request.as_deref(), Some(&b"request"[..]));

        let mut first_response = Some(bytes::Bytes::from_static(b"ori"));
        state
            .filter_response_body(&mut first_response, false)
            .expect("buffer first response chunk");
        assert_eq!(first_response.as_deref(), Some(&b""[..]));

        let mut final_response = Some(bytes::Bytes::from_static(b"gin"));
        state
            .filter_response_body(&mut final_response, true)
            .expect("emit buffered response");
        assert_eq!(final_response.as_deref(), Some(&b"filtered"[..]));
    }

    #[test]
    fn body_neutral_filter_does_not_receive_body_callbacks() {
        let mut state = start_state_with_mode(FailureMode::Closed, "none");
        let mut response = Some(bytes::Bytes::from_static(b"origin"));

        state
            .filter_response_body(&mut response, true)
            .expect("body-neutral filter passes through body");

        assert_eq!(response.as_deref(), Some(&b"origin"[..]));
    }

    #[test]
    fn body_input_limit_uses_the_filter_failure_posture() {
        let mut closed = start_state(FailureMode::Closed);
        let oversized = bytes::Bytes::from(vec![
            b'x';
            closed.filters[0].max_input_bytes.saturating_add(1)
        ]);
        let mut closed_body = Some(oversized.clone());
        let failure = closed
            .filter_request_body(&mut closed_body, false)
            .expect_err("closed posture rejects oversized callback input");
        assert_eq!(failure.code(), "input_limit");

        let mut open = start_state(FailureMode::Open);
        let mut open_body = Some(oversized.clone());
        open.filter_request_body(&mut open_body, false)
            .expect("open posture admits oversized callback input");
        assert_eq!(open_body.as_deref(), Some(oversized.as_ref()));
    }

    #[test]
    fn buffered_body_disables_only_the_admitting_filter_that_exceeds_its_limit() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(
            directory.path(),
            &[("small_open", "buffered"), ("later_closed", "buffered")],
        );
        let mut config = compile_config(&["small_open", "later_closed"]);
        config.origins[0].filters[0].failure_posture = Some(FailureMode::Open);
        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("compile mixed posture Proxy-Wasm chain");
        let mut state = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain")
            .start()
            .expect("start Proxy-Wasm chain");
        state.filters[0].max_input_bytes = 1;
        state.filters[1].max_input_bytes = 1024;
        state.max_buffer_bytes = 1;
        state.response_buffer_limit = 1;
        let mut body = Some(bytes::Bytes::from_static(b"origin"));

        state
            .filter_response_body(&mut body, true)
            .expect("later closed filter still processes the buffered body");

        assert!(!state.filters[0].response_body_enabled);
        assert!(state.filters[1].response_body_enabled);
        assert_eq!(body.as_deref(), Some(&b"filtered"[..]));
    }

    #[test]
    fn closed_response_body_filter_rejects_a_late_local_response() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle_with_wasm(
            directory.path(),
            &[("late_filter", "streamed")],
            LATE_RESPONSE_WASM,
        );
        let pipeline =
            CompiledPipeline::from_config_at(compile_config(&["late_filter"]), directory.path())
                .expect("compile closed late-response filter");
        let mut state = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain")
            .start()
            .expect("start Proxy-Wasm chain");
        let mut body = Some(bytes::Bytes::from_static(b"origin"));

        let failure = state
            .filter_response_body(&mut body, true)
            .expect_err("closed posture must close after a late local response");

        assert_eq!(failure.code(), "late_local_response");
    }

    #[test]
    fn open_response_body_filter_restores_the_chunk_and_deactivates() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle_with_wasm(
            directory.path(),
            &[("late_filter", "streamed")],
            LATE_RESPONSE_WASM,
        );
        let mut config = compile_config(&["late_filter"]);
        config.origins[0].filters[0].failure_posture = Some(FailureMode::Open);
        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("compile open late-response filter");
        let mut state = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain")
            .start()
            .expect("start Proxy-Wasm chain");
        let mut body = Some(bytes::Bytes::from_static(b"origin"));

        state
            .filter_response_body(&mut body, false)
            .expect("open posture must admit the committed response");

        assert_eq!(body.as_deref(), Some(&b"origin"[..]));
        assert!(!state.filters[0].active);
        assert!(state.filters[0].finalized);

        let mut later = Some(bytes::Bytes::from_static(b" later"));
        state
            .filter_response_body(&mut later, true)
            .expect("deactivated filter must stay out of later response chunks");
        assert_eq!(later.as_deref(), Some(&b" later"[..]));
    }

    #[test]
    fn local_response_preserves_guest_headers_and_grpc_status() {
        let local = sbproxy_extension::bundle::ProxyWasmLocalResponse {
            status: 429,
            grpc_status: Some(7),
            headers: vec![
                ("content-type".to_string(), "application/grpc".to_string()),
                ("x-guest".to_string(), "one".to_string()),
                ("x-guest".to_string(), "two".to_string()),
                ("connection".to_string(), "close".to_string()),
                ("content-length".to_string(), "999".to_string()),
                ("grpc-status".to_string(), "3".to_string()),
            ],
            body: bytes::Bytes::from_static(b"limited"),
        };
        let header = super::local_response_header(&local).expect("build local response header");

        assert_eq!(header.status.as_u16(), 429);
        assert_eq!(
            header
                .headers
                .get_all("x-guest")
                .iter()
                .map(|value| value.to_str().expect("text header"))
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(header.headers.get("grpc-status").unwrap(), "7");
        assert_eq!(header.headers.get("content-length").unwrap(), "7");
        assert!(!header.headers.contains_key("connection"));
        assert!(super::terminal_local_response_closes_downstream(
            http::Version::HTTP_11
        ));
        assert!(!super::terminal_local_response_closes_downstream(
            http::Version::HTTP_2
        ));
    }

    #[test]
    fn session_start_failure_skips_an_admitting_filter() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(
            directory.path(),
            &[("open_filter", "streamed"), ("healthy_filter", "streamed")],
        );
        let mut config = compile_config(&["open_filter", "healthy_filter"]);
        config.origins[0].filters[0].failure_posture = Some(FailureMode::Open);
        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("compile Proxy-Wasm chain");
        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        let mut attempts = 0usize;

        let state = chain
            .start_with(
                |filter| {
                    attempts += 1;
                    if attempts == 1 {
                        Err(sbproxy_extension::bundle::ProxyWasmCallFailure::RuntimeUnavailable)
                    } else {
                        filter.start_session()
                    }
                },
                |_, session| {
                    session.finish().expect("finish unwound session");
                },
            )
            .expect("open startup failure admits request");

        assert_eq!(state.filters.len(), 1);
        assert_eq!(state.filters[0].type_name, "healthy_filter");
    }

    #[test]
    fn session_start_failure_unwinds_prior_sessions_before_closed_error() {
        let directory = TempDir::new().expect("temporary bundle directory");
        write_bundle(
            directory.path(),
            &[
                ("started_filter", "streamed"),
                ("closed_filter", "streamed"),
            ],
        );
        let pipeline = CompiledPipeline::from_config_at(
            compile_config(&["started_filter", "closed_filter"]),
            directory.path(),
        )
        .expect("compile Proxy-Wasm chain");
        let chain = pipeline.proxy_wasm_filters[0]
            .as_ref()
            .expect("compiled Proxy-Wasm chain");
        let mut attempts = 0usize;
        let mut finished = Vec::new();

        let result = chain.start_with(
            |filter| {
                attempts += 1;
                if attempts == 2 {
                    Err(sbproxy_extension::bundle::ProxyWasmCallFailure::RuntimeUnavailable)
                } else {
                    filter.start_session()
                }
            },
            |type_name, session| {
                session.finish().expect("finish unwound session");
                assert!(session.is_finished());
                finished.push(type_name.to_string());
            },
        );
        let failure = match result {
            Ok(_) => panic!("closed startup failure must reject request"),
            Err(failure) => failure,
        };

        assert_eq!(failure.code(), "runtime_unavailable");
        assert_eq!(finished, ["started_filter"]);
    }
}
