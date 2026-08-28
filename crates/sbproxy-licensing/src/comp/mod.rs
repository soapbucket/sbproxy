//! IAB Content Authorization Marketplace Protocol (CoMP) bridge.
//!
//! Three well-known endpoints: `manifest.json` (catalog), `quote`
//! (signed price), `redeem` (acceptance to license-token bridge). The
//! CoMP redeem endpoint is the marketplace bridge that mints an
//! OLP-wire-compatible license token (see [`crate::comp::olp_bridge`])
//! once a
//! buyer's signed acceptance and payment proof verify.
//!
//! Quote signatures use this crate's own `comp-...` kid namespace
//! (see [`crate::keys`]), distinct from whatever `kid` the target
//! origin's OLP issuer uses, so a quote signature can never be
//! replayed as a license token or vice versa.

pub mod marketplace;
pub mod olp_bridge;
pub mod router;
pub mod serve;
pub mod types;

pub use marketplace::{
    quote_acceptance_hash, BuyerKeyRegistry, CompMarketplace, InMemoryBuyerKeyRegistry,
    COMP_ACCEPTANCE_SKEW_SECS, COMP_QUOTE_LEDGER_CAPACITY, COMP_QUOTE_VALIDITY_SECS,
};
pub use olp_bridge::{OlpBridgeClaims, OlpBridgeSigner, OLP_JWS_TYP};
pub use router::{comp_router, COMP_REQUEST_BODY_LIMIT};
pub use serve::{oversize, serve_manifest, serve_quote, serve_redeem, CompEndpoint, CompResponse};
pub use types::{
    compute_manifest_hash, CompAcceptance, CompAcquisition, CompAuthorization, CompBuyer,
    CompEndpoints, CompManifest, CompPaymentProof, CompPricing, CompPricingModel, CompPublisher,
    CompQuotePricing, CompQuoteRequest, CompQuoteResponse, CompRateCaps, CompRedeemRequest,
    CompRedeemResponse, CompRequestedVolume, CompSignature, CompTier, COMP_MANIFEST_CACHE_CONTROL,
    COMP_MANIFEST_CONTENT_TYPE, COMP_NO_STORE_CACHE_CONTROL, COMP_QUOTE_CONTENT_TYPE, COMP_VERSION,
};
