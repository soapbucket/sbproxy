//! One bounded reader for the downstream request body, shared by the
//! actions that answer from `request_filter`.
//!
//! The ordinary streaming cap lives in `proxy_http.rs`'s
//! `request_body_filter`, and Pingora only calls that hook for a
//! request it is going to forward. An action that writes its own
//! response and returns `Ok(true)` from `request_filter` never reaches
//! it, so a drain written inside such an action is the only thing
//! standing between a client and a per-worker allocation the size of
//! whatever that client chooses to send. A configured `request_limit`
//! policy does not close the gap either: it rejects an honest
//! `Content-Length` and otherwise only records
//! `RequestContext::body_size_limit`, which nothing on these paths
//! was reading.
//!
//! Every terminal drain therefore goes through
//! `read_capped_request_body`, which refuses past the cap before it
//! appends rather than after, and which is called before provider
//! dispatch, guardrails, and idempotency capture so "no upstream
//! contacted, no cache or idempotency write" follows from the ordering.

use bytes::Bytes;
use pingora_error::Result;
use pingora_proxy::Session;
use sbproxy_modules::DynamicHookMetadata;
use tracing::{debug, warn};

use super::send_error;
use crate::context::RequestContext;

/// Cap applied to a buffered body when the operator configured none.
///
/// A bound that exists only once somebody configures it is not a
/// bound, so this is a floor rather than a ceiling. 64 MiB is well
/// above any honest chat completion, transcription upload, or plugin
/// action payload, and well below what one worker can absorb per
/// request. It is the number the AI response relay has always used for
/// the same job, so an operator has one figure to know rather than two.
pub(super) const DEFAULT_BUFFERED_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Ceiling a configured maximum is clamped to.
///
/// An operator who asks for more than a gibibyte is describing a
/// streaming workload, and answering it from a buffer is the wrong
/// shape regardless of what the config says.
pub(super) const MAX_BUFFERED_BODY_BYTES: usize = 1024 * 1024 * 1024;

/// The length that produced a plan decision: the client's own claim.
pub(super) const PLAN_STAGE_DECLARED: &str = "declared_length";

/// The length that produced a plan decision: bytes actually received.
pub(super) const PLAN_STAGE_BUFFERED: &str = "buffered_length";

/// Resolve the byte cap for a body this process is going to hold whole.
///
/// `Some(0)` reads as "unset" rather than "refuse everything", which is
/// the behavior the AI relay shipped with and the one an operator who
/// wrote `max_body_size: 0` to mean "no opinion" expects.
pub(super) fn buffered_body_limit(configured: Option<usize>) -> usize {
    configured
        .filter(|maximum| *maximum > 0)
        .unwrap_or(DEFAULT_BUFFERED_BODY_BYTES)
        .min(MAX_BUFFERED_BODY_BYTES)
}

/// Drain the downstream request body, refusing anything past `cap`.
///
/// Returns `Ok(None)` once it has answered 413 itself, so the caller
/// returns without reaching an upstream, a cache, or an idempotency
/// record. A declared `Content-Length` over the cap is refused before
/// the first read, so an honest client hears no before it sends the
/// bytes; the per-chunk check then catches the chunked upload that
/// declares nothing, which is the case `request_limit` cannot see.
///
/// Each chunk is settled against the buffered-policy plan before it is
/// appended, so a hook's own `max_buffer_bytes` bounds the allocation
/// rather than being discovered once the buffer is already full.
///
/// `ctx.request_body_bytes` is maintained here because the access log
/// and the meter runtime read it for `bytes_in`, and a terminal action
/// never reaches the `request_body_filter` that otherwise keeps it.
pub(super) async fn read_capped_request_body(
    session: &mut Session,
    ctx: &mut RequestContext,
    cap: usize,
    message: &str,
) -> Result<Option<Bytes>> {
    let declared = session
        .req_header()
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if let Some(declared) = declared {
        if declared > cap {
            debug!(
                received = declared,
                cap, "terminal action refused a request body from its declared length"
            );
            ctx.response_status = Some(413);
            send_error(session, 413, message).await?;
            return Ok(None);
        }
    }

    let mut buffered = bytes::BytesMut::new();
    while let Some(chunk) = session.read_request_body().await? {
        let proposed = buffered.len().saturating_add(chunk.len());
        if proposed > cap {
            debug!(
                received = proposed,
                cap, "terminal action refused a streaming request body"
            );
            ctx.response_status = Some(413);
            send_error(session, 413, message).await?;
            return Ok(None);
        }
        // Before the append, not after it. A buffered policy that
        // declared a 1 KiB buffer must bound what this process holds,
        // and settling only once the read finished would let a chunked
        // client push the whole host cap through a control that asked
        // for a kilobyte.
        if !settle_buffered_policy_plan(session, ctx, proposed, None, PLAN_STAGE_BUFFERED).await? {
            return Ok(None);
        }
        ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(chunk.len() as u64);
        buffered.extend_from_slice(&chunk);
    }
    Ok(Some(buffered.freeze()))
}

/// Settle the buffered-policy plan against a body length.
///
/// Each buffered dynamic policy carries its own `max_buffer_bytes`, and
/// a body past that cap either skips the policy (an admitting posture,
/// which is recorded as the counterfactual it is) or refuses the
/// request (a closed posture). `stage` names which length produced the
/// decision so a warn line says whether the client declared the size or
/// streamed past it.
///
/// Returns `Ok(false)` once it has answered 413 itself.
pub(super) async fn settle_buffered_policy_plan(
    session: &mut Session,
    ctx: &mut RequestContext,
    proposed_len: usize,
    action_hook: Option<&DynamicHookMetadata>,
    stage: &'static str,
) -> Result<bool> {
    let skipped = match ctx
        .dynamic_request_body_plan
        .before_growth(proposed_len, action_hook)
    {
        Ok(skipped) => skipped,
        Err(overflow) => {
            let hook = overflow.metadata();
            debug!(
                target: "sbproxy::extension",
                bundle = hook.bundle_id(),
                hook = hook.hook_type(),
                policy_index = ?overflow.policy_index(),
                received = proposed_len,
                cap = overflow.cap(),
                stage,
                "dynamic hook rejected an action request body"
            );
            ctx.response_status = Some(413);
            send_error(session, 413, "request entity too large").await?;
            return Ok(false);
        }
    };
    for skipped_hook in skipped {
        let hook = skipped_hook.metadata();
        let posture = hook.failure_posture();
        warn!(
            target: "sbproxy::extension",
            bundle = hook.bundle_id(),
            hook = hook.hook_type(),
            policy_index = skipped_hook.policy_index(),
            received = proposed_len,
            cap = skipped_hook.cap(),
            failure_posture = posture.as_label(),
            stage,
            "skipping buffered dynamic policy whose action request body exceeded its cap"
        );
        if posture.guarantee_waived() || posture.records_counterfactual() {
            ctx.record_policy_decision(hook.hook_type(), posture.as_label());
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{buffered_body_limit, DEFAULT_BUFFERED_BODY_BYTES, MAX_BUFFERED_BODY_BYTES};

    #[test]
    fn an_unconfigured_body_is_still_bounded() {
        // The whole point of the default: a deployment that never
        // wrote `max_body_size` still has a ceiling, and `0` reads as
        // "no opinion" rather than "refuse every byte".
        assert_eq!(buffered_body_limit(None), DEFAULT_BUFFERED_BODY_BYTES);
        assert_eq!(buffered_body_limit(Some(0)), DEFAULT_BUFFERED_BODY_BYTES);
    }

    #[test]
    fn a_configured_body_limit_is_honored_and_clamped() {
        assert_eq!(buffered_body_limit(Some(1024)), 1024);
        assert_eq!(
            buffered_body_limit(Some(usize::MAX)),
            MAX_BUFFERED_BODY_BYTES
        );
    }
}
