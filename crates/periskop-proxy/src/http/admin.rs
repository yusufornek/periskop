//! The three read only endpoints (`proxy-api.md`, "periskop'a özgü uçlar").
//!
//! Three properties hold across all of them and each one is asserted below rather
//! than reviewed:
//!
//! 1. **Nothing here projects a secret.** `/admin/vault/status` is served by
//!    [`crate::vault::VaultStatus`], which already answers as a closed set of seven
//!    metadata fields; this module **calls** it and does not restate it. A second
//!    renderer would be a second place to add a field to, and the endpoint's whole
//!    promise is that it has no field capable of carrying an alias to value
//!    mapping.
//! 2. **`/admin/policy` cannot drift from the policy.** Every value is read off the
//!    loaded [`Policy`], including `entity_types`, which is **derived** by asking
//!    the resolver what each registered type's effective mode is. A projection with
//!    a written down list would keep answering `PERSON` after somebody set it to
//!    `allow`.
//! 3. **There is no write endpoint.** Not because none is implemented, but because
//!    `route::resolve` answers 405 to every method but `GET` on these paths, and
//!    `the_admin_surface_answers_no_method_but_get` fails if that changes. A
//!    sensitive control reachable over the network is attack surface the contract
//!    declined on purpose.

use crate::alias::EntityType;
use crate::policy::{resolve, Mode, Policy};

use super::json::quote;

/// `GET /admin/policy`, exactly the eight fields `proxy-api.md` shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyProjection {
    policy_id: String,
    policy_version: String,
    policy_hash: String,
    entity_types: Vec<&'static str>,
    alias_style: &'static str,
    date_policy: &'static str,
    tool_call_policy: &'static str,
    masking_profile: &'static str,
}

impl PolicyProjection {
    /// Every key this object can carry, in the order [`Self::to_json`] writes them.
    ///
    /// The same device `VaultStatus::FIELDS` uses, for the same reason: a closed
    /// set is assertable as "these and no ninth", where a list of forbidden words
    /// would pass a field called `context` carrying whatever it liked.
    pub const FIELDS: &'static [&'static str] = &[
        "policy_id",
        "policy_version",
        "policy_hash",
        "entity_types",
        "alias_style",
        "date_policy",
        "tool_call_policy",
        "masking_profile",
    ];

    /// Reads the projection off a loaded policy.
    pub fn of(policy: &Policy) -> Self {
        Self {
            policy_id: policy.policy_id().to_owned(),
            policy_version: policy.policy_version().to_owned(),
            policy_hash: policy.policy_hash().to_owned(),
            entity_types: governed_types(policy),
            alias_style: policy.alias_style().as_str(),
            date_policy: policy.date_policy().as_str(),
            tool_call_policy: policy.tool_call_policy().as_str(),
            // Derived, never configured: `proxy-policy.md` section 4.1 and K-11.
            // This is where "person names are being masked" is either claimed or
            // not, and it has to follow what actually ran.
            masking_profile: policy.masking_profile().as_str(),
        }
    }

    pub fn to_json(&self) -> String {
        let types: Vec<String> = self
            .entity_types
            .iter()
            .map(|tag| format!("\"{tag}\""))
            .collect();
        let fields = [
            format!("\"policy_id\":{}", quote(&self.policy_id)),
            format!("\"policy_version\":{}", quote(&self.policy_version)),
            format!("\"policy_hash\":{}", quote(&self.policy_hash)),
            format!("\"entity_types\":[{}]", types.join(",")),
            format!("\"alias_style\":\"{}\"", self.alias_style),
            format!("\"date_policy\":\"{}\"", self.date_policy),
            format!("\"tool_call_policy\":\"{}\"", self.tool_call_policy),
            format!("\"masking_profile\":\"{}\"", self.masking_profile),
        ];
        format!("{{{}}}", fields.join(","))
    }

    pub fn entity_types(&self) -> &[&'static str] {
        &self.entity_types
    }
}

/// The types this policy does something about, in `UPPER_SNAKE`.
///
/// Derived by asking [`resolve`] for the effective mode of each registered type at
/// the root scope, so the answer follows the rules an operator wrote. A type set to
/// `allow` is not governed and is not listed: listing it would tell a reader that a
/// value is being masked when the policy says it crosses.
///
/// `UPPER_SNAKE` comes from [`EntityType::tag`] rather than from a spelling written
/// here, which is D-17's decision: the policy file, the alias labels and this
/// endpoint all read one function.
fn governed_types(policy: &Policy) -> Vec<&'static str> {
    EntityType::ALL
        .into_iter()
        .filter(|entity| {
            resolve(policy.rules(), policy.default_mode(), &[], *entity) != Mode::Allow
        })
        .map(EntityType::tag)
        .collect()
}

/// `GET /admin/metrics`, in the Prometheus text exposition format.
///
/// Counters and quantiles, and by construction nothing else: every field is a
/// number. `proxy-api.md` is explicit that raw content and request bodies never
/// reach metrics, and the way that is guaranteed here is that there is no `String`
/// in this type to put one in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    requests_total: u64,
    refusals_total: u64,
    masked_entities_total: u64,
    stream_reassembly_errors_total: u64,
    /// Added latency samples, most recent first, bounded.
    added_latency_ms: Vec<u64>,
}

/// How many latency samples are kept.
///
/// Bounded because this is a long lived process on somebody's workstation and an
/// unbounded vector of samples is a memory leak with a schedule. The window is the
/// most recent ones, so the quantiles describe the proxy as it is running rather
/// than as it started.
const LATENCY_WINDOW: usize = 1024;

impl Metrics {
    pub fn record_request(&mut self, masked_entities: u32, added_latency_ms: u64) {
        self.requests_total += 1;
        self.masked_entities_total += u64::from(masked_entities);
        self.added_latency_ms.insert(0, added_latency_ms);
        self.added_latency_ms.truncate(LATENCY_WINDOW);
    }

    pub fn record_refusal(&mut self) {
        self.refusals_total += 1;
    }

    pub fn record_stream_reassembly_error(&mut self) {
        self.stream_reassembly_errors_total += 1;
    }

    pub fn requests_total(&self) -> u64 {
        self.requests_total
    }

    /// The nearest rank quantile over the window.
    ///
    /// Nearest rank rather than an interpolation, because an interpolated p99 over
    /// eleven samples reports a latency nothing measured.
    fn quantile(&self, fraction: f64) -> u64 {
        if self.added_latency_ms.is_empty() {
            return 0;
        }
        let mut sorted = self.added_latency_ms.clone();
        sorted.sort_unstable();
        let last = sorted.len() - 1;
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let rank = ((sorted.len() as f64) * fraction).ceil() as usize;
        sorted[rank.saturating_sub(1).min(last)]
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut counter = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };
        counter(
            "periskop_proxy_requests_total",
            "Requests that reached an upstream.",
            self.requests_total,
        );
        counter(
            "periskop_proxy_refusals_total",
            "Requests refused fail closed, before any upstream call.",
            self.refusals_total,
        );
        counter(
            "periskop_proxy_masked_entities_total",
            "Entities replaced by an alias.",
            self.masked_entities_total,
        );
        counter(
            "periskop_proxy_stream_reassembly_errors_total",
            "Stream events that could not be reassembled.",
            self.stream_reassembly_errors_total,
        );

        out.push_str(
            "# HELP periskop_proxy_added_latency_ms Latency this proxy added, in milliseconds.\n\
             # TYPE periskop_proxy_added_latency_ms summary\n",
        );
        for (quantile, fraction) in [("0.5", 0.5), ("0.95", 0.95), ("0.99", 0.99)] {
            out.push_str(&format!(
                "periskop_proxy_added_latency_ms{{quantile=\"{quantile}\"}} {}\n",
                self.quantile(fraction)
            ));
        }
        out
    }

    /// The content type `proxy-api.md` fixes for this endpoint.
    pub const CONTENT_TYPE: &'static str = "text/plain; version=0.0.4";
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::http::json::keys_of;
    use crate::policy::load::Policy;

    /// A minimal policy with `extra` spliced in **before** the `[default]` table.
    ///
    /// Before, not after: TOML table scoping would read every appended key as
    /// `default.<key>`, and the assertions below would be about keys nobody wrote.
    /// The same footgun is documented in `policy/load.rs`'s own tests.
    fn policy_text(extra: &str) -> String {
        format!(
            "policy_id = \"org-default\"\npolicy_version = \"1\"\n{extra}\n[default]\nmode = \"mask\"\n"
        )
    }

    fn load(text: &str) -> Policy {
        Policy::load(text, Path::new("."), None).unwrap_or_else(|refusal| panic!("{refusal}"))
    }

    #[test]
    fn the_projection_carries_the_eight_fields_the_contract_shows_and_no_ninth() {
        let projection = PolicyProjection::of(&load(&policy_text("")));
        assert_eq!(keys_of(&projection.to_json()), PolicyProjection::FIELDS);
    }

    /// The criterion task 87 states: the output cannot diverge from the policy
    /// file, pinned by deriving it from one.
    #[test]
    fn every_value_comes_out_of_the_policy_that_was_loaded() {
        let json = PolicyProjection::of(&load(&policy_text(
            "date_policy = \"block\"\n\
             tool_call_policy = \"reject\"\n\
             alias_style = \"opaque\"\n",
        )))
        .to_json();

        assert!(json.contains("\"policy_id\":\"org-default\""), "{json}");
        assert!(json.contains("\"policy_version\":\"1\""), "{json}");
        assert!(json.contains("\"date_policy\":\"block\""), "{json}");
        assert!(json.contains("\"tool_call_policy\":\"reject\""), "{json}");
        assert!(json.contains("\"alias_style\":\"opaque\""), "{json}");
        // Derived from `detection.ner.enabled`, which K-11 keeps false, so the
        // claim this build makes about person names is the weaker one.
        assert!(
            json.contains("\"masking_profile\":\"pattern+dictionary\""),
            "{json}"
        );
    }

    /// `entity_types` follows the rules rather than a list somebody typed.
    #[test]
    fn a_type_the_operator_allowed_stops_being_listed_as_governed() {
        let masked = PolicyProjection::of(&load(&policy_text("")));
        assert!(masked.entity_types().contains(&"EMAIL"));

        let allowed = PolicyProjection::of(&load(&policy_text(
            "[[rule]]\nentity = \"EMAIL\"\nmode = \"allow\"",
        )));
        assert!(
            !allowed.entity_types().contains(&"EMAIL"),
            "a hard coded list would still be claiming EMAIL is masked: {:?}",
            allowed.entity_types()
        );
        // And the rest are untouched, so this is a derivation and not a switch
        // that empties the list.
        assert!(allowed.entity_types().contains(&"IBAN"));
    }

    #[test]
    fn the_type_tags_are_upper_snake() {
        let projection = PolicyProjection::of(&load(&policy_text("")));
        for tag in projection.entity_types() {
            assert!(
                tag.chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
                "{tag} is not UPPER_SNAKE"
            );
        }
        // The contract's own example values, spelled the way D-17 fixed them.
        for expected in ["EMAIL", "CREDIT_CARD", "API_KEY", "TCKN", "PERSON"] {
            assert!(
                projection.entity_types().contains(&expected),
                "{expected} is missing from {:?}",
                projection.entity_types()
            );
        }
    }

    #[test]
    fn the_policy_hash_is_the_full_blake3_hex_and_not_a_prefix() {
        let json = PolicyProjection::of(&load(&policy_text(""))).to_json();
        let hash = json
            .split("\"policy_hash\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        // K-08: blake3-256, 64 hex characters, not sha256 and not truncated.
        assert_eq!(hash.len(), 64, "{json}");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "{json}");
    }

    #[test]
    fn metrics_are_numbers_and_the_quantiles_are_measured_values() {
        let mut metrics = Metrics::default();
        for sample in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            metrics.record_request(1, sample);
        }
        metrics.record_refusal();
        metrics.record_stream_reassembly_error();

        let rendered = metrics.render();
        assert!(
            rendered.contains("periskop_proxy_requests_total 10"),
            "{rendered}"
        );
        assert!(
            rendered.contains("periskop_proxy_refusals_total 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("periskop_proxy_masked_entities_total 10"),
            "{rendered}"
        );
        assert!(
            rendered.contains("periskop_proxy_stream_reassembly_errors_total 1"),
            "{rendered}"
        );
        // Nearest rank: the reported p50 is a sample that was taken.
        assert!(
            rendered.contains("periskop_proxy_added_latency_ms{quantile=\"0.5\"} 50"),
            "{rendered}"
        );
        assert!(
            rendered.contains("periskop_proxy_added_latency_ms{quantile=\"0.99\"} 100"),
            "{rendered}"
        );
    }

    #[test]
    fn no_request_content_can_reach_the_metrics_surface() {
        // Asserted over the rendering rather than over the type, because the
        // rendering is what leaves the process. Every line is `name value` or a
        // comment, and every value parses as a number.
        let mut metrics = Metrics::default();
        metrics.record_request(3, 12);
        for line in metrics.render().lines() {
            if line.starts_with('#') {
                continue;
            }
            let value = line.rsplit(' ').next().unwrap_or_default();
            assert!(
                value.parse::<f64>().is_ok(),
                "a metric line carries something that is not a number: {line}"
            );
        }
    }

    #[test]
    fn an_empty_window_reports_zero_rather_than_refusing() {
        // A proxy that has served nothing still has to answer this endpoint: a
        // scrape that fails is read as the proxy being down.
        let rendered = Metrics::default().render();
        assert!(
            rendered.contains("periskop_proxy_added_latency_ms{quantile=\"0.5\"} 0"),
            "{rendered}"
        );
    }
}
