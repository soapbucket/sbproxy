//! Exact money.
//!
//! Amounts are integer micros of one major currency unit, paired with an
//! explicit ISO 4217 alphabetic code. There is no floating point in this
//! module and no implicit rounding anywhere in the crate. A conversion to a
//! provider base unit either lands exactly on an integer or fails.
//!
//! The unit choice matches the quote unit the AI crawl policy already
//! produces, so a price crosses the boundary without a lossy re-scaling.
//! Micros divide evenly into every base unit a supported rail uses today:
//! two decimals for card currencies, six for USDC, eight for on-chain
//! bitcoin, and eleven for millisatoshi once the satoshi scale is applied.

use serde::{Deserialize, Serialize};

use crate::error::BillingError;

/// A validated ISO 4217 alphabetic currency code.
///
/// The stored form is always three uppercase ASCII letters. Providers that
/// want a lowercase code, such as Stripe, get it from
/// [`CurrencyCode::to_provider_string`]; the durable record keeps the
/// uppercase form so two spellings can never key two different rows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    /// Parses and normalizes a currency code.
    ///
    /// Surrounding whitespace is rejected rather than trimmed, because a
    /// code with whitespace in it came from a place that is not validating
    /// its input and the caller should learn that.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidCurrency`] unless the input is exactly
    /// three ASCII alphabetic characters.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        if input.len() != 3 || !input.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(BillingError::InvalidCurrency);
        }
        Ok(Self(input.to_ascii_uppercase()))
    }

    /// Returns the normalized uppercase code.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the lowercase spelling providers such as Stripe require.
    pub fn to_provider_string(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

impl std::fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An exact amount of money.
///
/// `amount_micros` counts millionths of one major unit. `currency` holds the
/// normalized uppercase ISO code; construct through [`Money::new`] so it is
/// normalized, and call [`Money::validate`] on any value that arrived over
/// the wire before trusting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    /// Millionths of one major currency unit. Always strictly positive.
    pub amount_micros: u64,
    /// Normalized uppercase ISO 4217 alphabetic currency code.
    pub currency: String,
}

impl Money {
    /// Micros in one major currency unit.
    pub const MICROS_PER_UNIT: u64 = 1_000_000;

    /// Decimal places the micro scale itself carries.
    pub const MICRO_DECIMALS: u8 = 6;

    /// Largest base-unit precision this crate will convert to.
    ///
    /// Eighteen covers every asset a supported rail quotes today, including
    /// wei-scaled tokens, and keeps the checked multiplication inside `u64`
    /// for every amount the store can hold.
    pub const MAX_DECIMALS: u8 = 18;

    /// Builds a validated amount.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidAmount`] when the amount is zero or
    /// larger than the durable store can hold, and
    /// [`BillingError::InvalidCurrency`] when the code is not an ISO
    /// alphabetic triple.
    pub fn new(amount_micros: u64, currency: &str) -> Result<Self, BillingError> {
        let currency = CurrencyCode::parse(currency)?;
        let money = Self {
            amount_micros,
            currency: currency.as_str().to_string(),
        };
        money.validate()?;
        Ok(money)
    }

    /// Checks that a deserialized amount is positive, bounded, and normalized.
    ///
    /// The store persists micros in a SQLite `INTEGER`, which is a signed
    /// 64-bit column, so anything above `i64::MAX` is rejected here rather
    /// than silently wrapping on the way in.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidAmount`] or
    /// [`BillingError::InvalidCurrency`].
    pub fn validate(&self) -> Result<(), BillingError> {
        if self.amount_micros == 0 || self.amount_micros > i64::MAX as u64 {
            return Err(BillingError::InvalidAmount);
        }
        let parsed = CurrencyCode::parse(&self.currency)?;
        if parsed.as_str() != self.currency {
            return Err(BillingError::InvalidCurrency);
        }
        Ok(())
    }

    /// Returns the validated currency code.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidCurrency`] when the stored string is
    /// not an ISO alphabetic triple.
    pub fn currency_code(&self) -> Result<CurrencyCode, BillingError> {
        CurrencyCode::parse(&self.currency)
    }

    /// Converts to an integer count of provider base units.
    ///
    /// `decimals` is the provider's declared precision: two for a card
    /// currency charged in cents, six for USDC, eight for on-chain bitcoin.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidPrecision`] when `decimals` exceeds
    /// [`Money::MAX_DECIMALS`], and [`BillingError::AmountNotRepresentable`]
    /// when the conversion would drop a remainder or overflow `u64`.
    pub fn to_base_units(&self, decimals: u8) -> Result<u64, BillingError> {
        self.validate()?;
        if decimals > Self::MAX_DECIMALS {
            return Err(BillingError::InvalidPrecision);
        }
        if decimals <= Self::MICRO_DECIMALS {
            let divisor = pow10(Self::MICRO_DECIMALS - decimals)?;
            if !self.amount_micros.is_multiple_of(divisor) {
                return Err(BillingError::AmountNotRepresentable);
            }
            Ok(self.amount_micros / divisor)
        } else {
            let multiplier = pow10(decimals - Self::MICRO_DECIMALS)?;
            self.amount_micros
                .checked_mul(multiplier)
                .ok_or(BillingError::AmountNotRepresentable)
        }
    }

    /// Renders the base-unit count as the decimal string rails put on the wire.
    ///
    /// x402 sends `maxAmountRequired` as an integer string of atomic units,
    /// and the durable requirement stores exactly the string that was
    /// advertised so the credential can be checked against it byte for byte.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`Money::to_base_units`].
    pub fn to_base_unit_string(&self, decimals: u8) -> Result<String, BillingError> {
        Ok(self.to_base_units(decimals)?.to_string())
    }

    /// Rebuilds an amount from a base-unit count and a declared precision.
    ///
    /// This is the inverse used when checking that a rail's advertised
    /// settlement amount still means the price that was quoted.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidPrecision`] for an out-of-range
    /// precision and [`BillingError::AmountNotRepresentable`] when the
    /// base-unit count cannot be expressed in whole micros.
    pub fn from_base_units(
        base_units: u64,
        decimals: u8,
        currency: &str,
    ) -> Result<Self, BillingError> {
        if decimals > Self::MAX_DECIMALS {
            return Err(BillingError::InvalidPrecision);
        }
        let amount_micros = if decimals <= Self::MICRO_DECIMALS {
            let multiplier = pow10(Self::MICRO_DECIMALS - decimals)?;
            base_units
                .checked_mul(multiplier)
                .ok_or(BillingError::AmountNotRepresentable)?
        } else {
            let divisor = pow10(decimals - Self::MICRO_DECIMALS)?;
            if !base_units.is_multiple_of(divisor) {
                return Err(BillingError::AmountNotRepresentable);
            }
            base_units / divisor
        };
        Self::new(amount_micros, currency)
    }

    /// Returns the lowercase currency spelling providers such as Stripe want.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidCurrency`] when the stored code is not
    /// an ISO alphabetic triple.
    pub fn provider_currency(&self) -> Result<String, BillingError> {
        Ok(self.currency_code()?.to_provider_string())
    }
}

/// Ten raised to `exponent`, refusing anything the crate does not support.
fn pow10(exponent: u8) -> Result<u64, BillingError> {
    if exponent > Money::MAX_DECIMALS {
        return Err(BillingError::InvalidPrecision);
    }
    10u64
        .checked_pow(u32::from(exponent))
        .ok_or(BillingError::InvalidPrecision)
}
