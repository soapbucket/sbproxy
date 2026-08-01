//! Compiling one priced route into one signed payment requirement.
//!
//! The crawl policy knows what a request costs. The billing crate knows how
//! to settle it. This module is the single translation between them, and it
//! is deliberately the only one: every rail-specific value an adapter later
//! reads is copied here, from the compiled configuration, into the typed
//! [`RequirementTerms`] that travel with the requirement.
//!
//! # One source for every value
//!
//! An adapter cannot consult a second price, address, facilitator, network,
//! payment-method list, capture mode, backend, or expiry. That is what makes
//! the signed digest meaningful: if the amount an adapter charges could come
//! from anywhere but the requirement, the signature over the requirement
//! would not bind the charge.
//!
//! # Conversion is exact or it fails
//!
//! Prices are integer micros of a major unit. Converting to a provider's base
//! unit uses [`settlement_amount`], which refuses a remainder rather than
//! rounding it away. A route priced finer than the rail's smallest unit is a
//! configuration error surfaced at challenge time, not a fraction of a cent
//! silently donated to or taken from the payer.

use sbproxy_billing::types::{
    AdvertisedRail, PaymentProtocol, PaymentRequirementDraft, RequirementTerms, SettlementRail,
};
use sbproxy_billing::Money as BillingMoney;
use sbproxy_config::payments::{
    settlement_amount, AdvertisedRailName, AmountConversionError, LightningBackend, PaymentsConfig,
    PaymentsConfigError,
};

use super::ai_crawl::Money;

/// Why a priced route could not become a payment requirement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequirementCompileError {
    /// The advertised rail has no configured backend.
    #[error("route advertises the {rail} rail but proxy.payments configures no backend for it")]
    RailNotConfigured {
        /// The rail the route advertised.
        rail: &'static str,
    },

    /// The route's price is not exactly representable on the rail.
    #[error(
        "route price is not exactly representable in the {rail} rail's settlement unit: {source}"
    )]
    Amount {
        /// The rail whose precision refused the price.
        rail: &'static str,
        /// The exact conversion failure.
        #[source]
        source: AmountConversionError,
    },

    /// The route's currency is not the rail's configured quote currency.
    #[error("route prices in {route_currency} but the {rail} rail quotes in {rail_currency}; the proxy performs no currency conversion")]
    CurrencyMismatch {
        /// The rail that disagreed.
        rail: &'static str,
        /// What the route priced in.
        route_currency: String,
        /// What the rail quotes in.
        rail_currency: String,
    },

    /// The configuration itself could not answer.
    #[error("{0}")]
    Config(#[from] PaymentsConfigError),
}

/// Compiles priced routes into payment requirement drafts.
///
/// Borrows the compiled configuration rather than copying it, so a reload
/// that replaces the configuration replaces every compiler built from it.
pub struct PaymentRequirementCompiler<'a> {
    config: &'a PaymentsConfig,
}

/// Everything about one priced request the compiler cannot infer.
pub struct RequirementContext<'a> {
    /// Stable identifier for this requirement within the tenant.
    pub requirement_id: &'a str,
    /// The quote this requirement prices.
    pub quote_id: &'a str,
    /// The tenant the intent belongs to.
    pub tenant_id: &'a str,
    /// The origin the paid request targets.
    pub origin_id: &'a str,
    /// The route the paid request targets.
    pub route: &'a str,
    /// The matched tier price.
    pub price: &'a Money,
    /// The rail this challenge advertises.
    pub advertised_rail: AdvertisedRailName,
    /// RFC 9530 digest binding the challenge to the request body, when the
    /// request carried one.
    pub request_digest: Option<String>,
    /// Wall-clock expiry of the challenge, in milliseconds since the epoch.
    pub expires_at_ms: i64,
}

impl<'a> PaymentRequirementCompiler<'a> {
    /// Builds a compiler over one compiled payments configuration.
    #[must_use]
    pub const fn new(config: &'a PaymentsConfig) -> Self {
        Self { config }
    }

    /// Compiles one advertised rail into an immutable requirement draft.
    ///
    /// The draft is everything that is knowable before the rail creates
    /// whatever provider object its challenge names. Rails with nothing to
    /// create are complete at this point; the rest gain only a non-secret
    /// provider handle afterwards, which is why the draft is hashed
    /// separately from the final requirement.
    ///
    /// # Errors
    ///
    /// Returns [`RequirementCompileError`] for a rail with no backend, a
    /// price the rail cannot represent exactly, or a currency the rail does
    /// not quote in.
    pub fn draft(
        &self,
        context: &RequirementContext<'_>,
    ) -> Result<PaymentRequirementDraft, RequirementCompileError> {
        let rail_name = context.advertised_rail.as_str();
        let quote_currency = self
            .config
            .quote_currency_for(context.advertised_rail)?
            .ok_or(RequirementCompileError::RailNotConfigured { rail: rail_name })?;

        if !context.price.currency.eq_ignore_ascii_case(quote_currency) {
            return Err(RequirementCompileError::CurrencyMismatch {
                rail: rail_name,
                route_currency: context.price.currency.clone(),
                rail_currency: quote_currency.to_string(),
            });
        }

        let (settlement_rail, protocol, decimals, terms, network, asset, pay_to, method, intent) =
            self.rail_shape(context.advertised_rail)?;

        let settlement =
            settlement_amount(context.price.amount_micros, decimals).map_err(|source| {
                RequirementCompileError::Amount {
                    rail: rail_name,
                    source,
                }
            })?;

        Ok(PaymentRequirementDraft {
            requirement_id: context.requirement_id.to_string(),
            protocol,
            advertised_rail: advertised(context.advertised_rail),
            settlement_rail,
            method,
            intent,
            network,
            asset,
            pay_to,
            amount: BillingMoney {
                amount_micros: context.price.amount_micros,
                currency: context.price.currency.to_uppercase(),
            },
            settlement_amount: settlement,
            settlement_decimals: decimals,
            terms,
            quote_id: context.quote_id.to_string(),
            tenant_id: context.tenant_id.to_string(),
            origin_id: context.origin_id.to_string(),
            route: context.route.to_string(),
            expires_at_ms: context.expires_at_ms,
            request_digest: context.request_digest.clone(),
        })
    }

    /// Reads every rail-specific value out of the compiled configuration.
    ///
    /// One match, so adding a rail cannot half-populate a requirement: the
    /// tuple is the complete set of fields a rail contributes.
    #[allow(clippy::type_complexity)]
    fn rail_shape(
        &self,
        rail: AdvertisedRailName,
    ) -> Result<
        (
            SettlementRail,
            PaymentProtocol,
            u8,
            RequirementTerms,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
        ),
        RequirementCompileError,
    > {
        let name = rail.as_str();
        match rail {
            AdvertisedRailName::X402 => {
                let config = self
                    .config
                    .rails
                    .x402
                    .as_ref()
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                // The first facilitator is the selected one. Fallback is a
                // fresh challenge, never a second try on a signed
                // requirement, so selection happens exactly here.
                let facilitator = config
                    .facilitators
                    .first()
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                Ok((
                    SettlementRail::X402,
                    PaymentProtocol::X402V2,
                    config.asset_decimals,
                    RequirementTerms::X402Exact {
                        facilitator_url: facilitator.facilitator_url.clone(),
                        max_timeout_seconds: config.max_timeout_seconds,
                        extra: config
                            .extra
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect(),
                    },
                    Some(config.network.clone()),
                    Some(config.asset.clone()),
                    Some(config.pay_to.clone()),
                    config.scheme.clone(),
                    config.scheme.clone(),
                ))
            }
            AdvertisedRailName::Mpp => {
                let config = self
                    .config
                    .rails
                    .stripe
                    .as_ref()
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                let protocol = self
                    .config
                    .protocols
                    .payment_auth
                    .as_ref()
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                Ok((
                    // Payment Auth is a presentation protocol, not a
                    // settler. It advertises as `mpp` and settles on Stripe;
                    // there is no `Mpp` settlement rail to route to.
                    SettlementRail::Stripe,
                    PaymentProtocol::PaymentAuthDraft01,
                    config.currency_decimals,
                    RequirementTerms::PaymentAuthStripeCharge {
                        business_network_id: config.business_network_id.clone(),
                        payment_method_types: config.payment_method_types.clone(),
                        account_context: config.account_context.clone(),
                    },
                    None,
                    None,
                    None,
                    protocol.method.clone(),
                    protocol.intent.clone(),
                ))
            }
            AdvertisedRailName::Stripe => {
                let config = self
                    .config
                    .rails
                    .stripe
                    .as_ref()
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                // Direct mode is only advertisable when the operator turned
                // it on. It charges a card the proxy holds no credential
                // for, so an omitted block means off, never default on.
                let direct = config
                    .direct_payment_intent
                    .as_ref()
                    .filter(|direct| direct.enabled)
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                Ok((
                    SettlementRail::Stripe,
                    PaymentProtocol::StripePaymentIntentV1,
                    config.currency_decimals,
                    RequirementTerms::StripePaymentIntent {
                        payment_method_types: config.payment_method_types.clone(),
                        capture_method: direct.capture_method.clone(),
                        account_context: config.account_context.clone(),
                    },
                    None,
                    None,
                    None,
                    "stripe".to_string(),
                    "payment_intent".to_string(),
                ))
            }
            AdvertisedRailName::Lightning => {
                let backend = self
                    .config
                    .lightning_backend()?
                    .ok_or(RequirementCompileError::RailNotConfigured { rail: name })?;
                let (settlement_rail, decimals, expiry) =
                    match backend {
                        LightningBackend::Cln => {
                            let config =
                                self.config.rails.lightning_cln.as_ref().ok_or(
                                    RequirementCompileError::RailNotConfigured { rail: name },
                                )?;
                            (
                                SettlementRail::LightningCln,
                                config.settlement_decimals,
                                config.invoice_expiry_seconds,
                            )
                        }
                        LightningBackend::Lnd => {
                            let config =
                                self.config.rails.lightning_lnd.as_ref().ok_or(
                                    RequirementCompileError::RailNotConfigured { rail: name },
                                )?;
                            (
                                SettlementRail::LightningLnd,
                                config.settlement_decimals,
                                config.invoice_expiry_seconds,
                            )
                        }
                    };
                Ok((
                    settlement_rail,
                    PaymentProtocol::LightningInvoice,
                    decimals,
                    RequirementTerms::LightningInvoice {
                        backend: backend.as_str().to_string(),
                        invoice_expiry_seconds: expiry,
                    },
                    None,
                    None,
                    None,
                    "lightning".to_string(),
                    "invoice".to_string(),
                ))
            }
        }
    }
}

/// Maps the configuration's rail name onto the billing crate's enum.
///
/// Two enums rather than one because they answer different questions: the
/// configuration's names what an operator may write, the billing crate's
/// names what a challenge may advertise. They agree today, and this function
/// is where they would stop agreeing loudly rather than silently.
const fn advertised(rail: AdvertisedRailName) -> AdvertisedRail {
    match rail {
        AdvertisedRailName::X402 => AdvertisedRail::X402,
        AdvertisedRailName::Mpp => AdvertisedRail::Mpp,
        AdvertisedRailName::Stripe => AdvertisedRail::Stripe,
        AdvertisedRailName::Lightning => AdvertisedRail::Lightning,
    }
}
