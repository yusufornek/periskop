//! The three legged declaration, and the rule that one leg missing means refuse.
//!
//! `proxy-api.md`'s tool-call decision is a trade: structured arguments and the
//! Responses surface reach the provider **unmasked**, because masking a
//! `{"limit": 50}` without knowing the schema turns a correct call into a
//! confidently wrong one, and refusing outright pushes an organisation into taking
//! the proxy out of the path. The trade holds on one condition, stated as a
//! sentence: "geçiş vardır ama sessiz geçiş yoktur", and the declaration is made in
//! three places at once.
//!
//! 1. the response header `x-periskop-degraded`,
//! 2. `ProxyEvent.degraded_reasons[]`,
//! 3. a finding, `kind = "unmasked_passthrough"`.
//!
//! "Üçünden biri üretilemiyorsa istek **reddedilir**." That is why this is a type
//! with a fallible constructor rather than three lines at a call site: the request
//! path cannot forward an unmasked body without holding one of these, and one of
//! these cannot exist with a leg missing.

use crate::detect::DegradedReason;

use super::errors::{ProxyError, Refusal};

/// The finding a passed-through gap produces (`findings-schema.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub component: &'static str,
    pub rule_id: &'static str,
}

/// What is being declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// Structured tool-call or tool-result arguments in an otherwise masked body.
    ToolArguments,
    /// A whole endpoint with no masking (Responses, Assistants).
    UnsupportedEndpoint,
}

impl Gap {
    const fn reason(self) -> DegradedReason {
        match self {
            Self::ToolArguments => DegradedReason::ToolArgumentsUnmasked,
            Self::UnsupportedEndpoint => DegradedReason::EndpointUnsupportedPassthrough,
        }
    }

    const fn rule_id(self) -> &'static str {
        match self {
            Self::ToolArguments => "proxy.tool-call.unmasked-arguments",
            Self::UnsupportedEndpoint => "proxy.endpoint.unsupported-passthrough",
        }
    }
}

/// A gap that has been declared in all three places.
///
/// Holding one is the permission to forward an unmasked body. There is no
/// constructor that skips a leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared {
    gap: Gap,
    reason: DegradedReason,
    finding: Finding,
}

impl Declared {
    /// Builds the declaration, or refuses.
    ///
    /// `header_available` and `event_available` are what the caller knows about
    /// its own two legs: a response that has already been committed cannot take a
    /// header, and a request with no event record cannot carry a reason. Passing
    /// `false` for either is what turns the trade off and the request into a
    /// refusal, which is the contract's own condition rather than an extra one.
    pub fn make(gap: Gap, header_available: bool, event_available: bool) -> Result<Self, Refusal> {
        if !header_available || !event_available {
            return Err(Refusal::new(
                ProxyError::ToolArgumentsRejected,
                format!(
                    "an unmasked passthrough ({}) could not be declared in all three \
                     places, so it is refused instead: a gap that cannot be declared \
                     is the one thing the pass-through decision does not permit",
                    gap.rule_id()
                ),
            ));
        }
        Ok(Self {
            gap,
            reason: gap.reason(),
            finding: Finding {
                kind: "unmasked_passthrough",
                component: "proxy",
                rule_id: gap.rule_id(),
            },
        })
    }

    pub const fn reason(&self) -> DegradedReason {
        self.reason
    }

    pub const fn finding(&self) -> Finding {
        self.finding
    }

    pub const fn gap(&self) -> Gap {
        self.gap
    }
}

/// The refusal `tool_call_policy = "reject"` produces.
pub fn rejected() -> Refusal {
    Refusal::new(
        ProxyError::ToolArgumentsRejected,
        "the policy sets tool_call_policy = \"reject\" and this request carries \
         structured tool-call arguments",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_gap_carries_all_three_legs() {
        let declared = Declared::make(Gap::ToolArguments, true, true).unwrap();
        assert_eq!(declared.reason(), DegradedReason::ToolArgumentsUnmasked);
        assert_eq!(declared.reason().as_str(), "tool_arguments_unmasked");
        assert_eq!(
            declared.finding(),
            Finding {
                kind: "unmasked_passthrough",
                component: "proxy",
                rule_id: "proxy.tool-call.unmasked-arguments",
            }
        );
    }

    #[test]
    fn the_endpoint_level_gap_is_counted_apart_from_the_field_level_one() {
        // `proxy-events.md` is explicit that these two may not stand in for each
        // other: one is a field inside a masked request, the other is a whole
        // endpoint where no layer ran, and they are measured separately.
        let field = Declared::make(Gap::ToolArguments, true, true).unwrap();
        let endpoint = Declared::make(Gap::UnsupportedEndpoint, true, true).unwrap();
        assert_ne!(field.reason(), endpoint.reason());
        assert_ne!(field.finding().rule_id, endpoint.finding().rule_id);
        assert_eq!(
            endpoint.reason().as_str(),
            "endpoint_unsupported_passthrough"
        );
    }

    #[test]
    fn a_leg_that_cannot_be_produced_turns_the_pass_through_into_a_refusal() {
        for (header, event) in [(false, true), (true, false), (false, false)] {
            let refusal = Declared::make(Gap::ToolArguments, header, event)
                .expect_err("a gap was passed through undeclared");
            assert_eq!(refusal.error(), ProxyError::ToolArgumentsRejected);
            assert_eq!(refusal.status(), 400);
        }
    }

    #[test]
    fn the_reject_policy_refuses_with_the_contract_s_own_value() {
        let refusal = rejected();
        assert_eq!(refusal.error(), ProxyError::ToolArgumentsRejected);
        assert_eq!(refusal.status(), 400);
    }
}
