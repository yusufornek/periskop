//! What `GET /admin/vault/status` is allowed to say about the vault.
//!
//! `proxy-api.md` fixes the field names and their permitted values, and one
//! sentence of it is the reason this type exists at all: the endpoint "**asla**
//! takma ad↔gerçek değer eşlemesinin içeriğini döndürmez". A projection with no
//! field capable of carrying a mapping is a stronger guarantee than an endpoint
//! that is careful, because carefulness is a property of whoever edits it next.
//!
//! There is no HTTP surface in this crate yet; the endpoint is a later task. What
//! is here is the value that task will serialise, so that the `integrity` value a
//! refusal produced and the one an operator reads cannot be two different things.

use std::path::Path;

use super::error::Integrity;
use super::Storage;

/// The AEAD, fixed by ADR-007's D-14 revision and K-17.
const AEAD: &str = "xchacha20poly1305";

/// Whether the vault is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultState {
    Sealed,
    Unsealed,
}

impl VaultState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Unsealed => "unsealed",
        }
    }
}

/// Metadata, and by construction nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    state: VaultState,
    backend: Storage,
    path: Option<String>,
    integrity: Integrity,
    entries: usize,
    memory_locked: bool,
}

impl VaultStatus {
    pub(super) fn new(
        state: VaultState,
        backend: Storage,
        path: Option<&Path>,
        integrity: Integrity,
        entries: usize,
    ) -> Self {
        Self {
            state,
            backend,
            // Only meaningful in `file` mode (`proxy-api.md`), and absent rather
            // than empty in `memory` mode: an empty string would read as a path
            // nobody could find.
            path: path.map(|path| path.display().to_string()),
            integrity,
            entries,
            // `periskop-memguard` is the crate ADR-016 section 5 quarantines the
            // `mlock` call in, and no wave has built it. Reporting `false` is the
            // honest answer and the one KG-019 describes: the pages are not
            // locked, so a reader must not believe they are.
            memory_locked: false,
        }
    }

    pub fn integrity(&self) -> Integrity {
        self.integrity
    }

    pub fn state(&self) -> VaultState {
        self.state
    }

    pub fn backend(&self) -> Storage {
        self.backend
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    /// The response body `proxy-api.md` describes.
    ///
    /// Rendered here rather than by whatever serves it, so that the one place a
    /// vault turns into bytes for a client is a place with no access to a record.
    pub fn to_json(&self) -> String {
        let mut fields = vec![
            format!("\"vault_state\":\"{}\"", self.state.as_str()),
            format!("\"backend\":\"{}\"", self.backend.as_str()),
        ];
        if let Some(path) = &self.path {
            fields.push(format!("\"path\":{}", quote(path)));
        }
        fields.push(format!("\"aead\":\"{AEAD}\""));
        fields.push(format!("\"integrity\":\"{}\"", self.integrity.as_str()));
        fields.push(format!("\"memory_locked\":{}", self.memory_locked));
        fields.push(format!("\"entries_count\":{}", self.entries));
        format!("{{{}}}", fields.join(","))
    }
}

/// Escapes the one field that is not drawn from a closed vocabulary.
///
/// Every other value in this object is an enum variant or a number. A path comes
/// from the operator's command line and can hold a quote or a backslash, and a
/// response body that is not valid JSON is a client that cannot read the status of
/// a vault that is refusing to open.
fn quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            control if control < ' ' => {
                quoted.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_vault_reports_no_path_and_an_intact_chain() {
        let status = VaultStatus::new(
            VaultState::Unsealed,
            Storage::Memory,
            None,
            Integrity::Ok,
            3,
        );
        let json = status.to_json();

        assert!(json.contains("\"backend\":\"memory\""), "{json}");
        assert!(json.contains("\"integrity\":\"ok\""), "{json}");
        assert!(json.contains("\"entries_count\":3"), "{json}");
        assert!(json.contains("\"aead\":\"xchacha20poly1305\""), "{json}");
        // `proxy-api.md`: the field is only meaningful in `file` mode.
        assert!(!json.contains("\"path\""), "{json}");
    }

    #[test]
    fn a_file_vault_reports_its_path_and_its_integrity_value() {
        let status = VaultStatus::new(
            VaultState::Sealed,
            Storage::File,
            Some(Path::new("/home/o/.periskop/vault.psk")),
            Integrity::CounterRollback,
            0,
        );
        let json = status.to_json();

        assert!(json.contains("\"vault_state\":\"sealed\""), "{json}");
        assert!(json.contains("\"backend\":\"file\""), "{json}");
        assert!(
            json.contains("\"path\":\"/home/o/.periskop/vault.psk\""),
            "{json}"
        );
        assert!(
            json.contains("\"integrity\":\"counter_rollback\""),
            "{json}"
        );
    }

    #[test]
    fn a_path_with_a_quote_in_it_does_not_break_the_response() {
        let status = VaultStatus::new(
            VaultState::Sealed,
            Storage::File,
            Some(Path::new("/tmp/a\"b\\c/vault.psk")),
            Integrity::Ok,
            0,
        );
        let json = status.to_json();
        assert!(
            json.contains(r#""path":"/tmp/a\"b\\c/vault.psk""#),
            "{json}"
        );
    }

    /// The endpoint's whole promise, as a property of the type.
    #[test]
    fn there_is_no_field_that_could_carry_a_mapping() {
        // Every accessor on this type returns an enum, a number or the path the
        // operator asked for. If a future field carried an alias or a value, this
        // list would have to grow, which is the review this test is here to force.
        let status = VaultStatus::new(
            VaultState::Unsealed,
            Storage::File,
            Some(Path::new("/tmp/vault.psk")),
            Integrity::Ok,
            10_000,
        );
        let json = status.to_json();
        for field in ["alias", "value", "session", "seed", "record", "nonce"] {
            assert!(!json.contains(field), "{json} names {field}");
        }
        assert_eq!(status.entries(), 10_000);
        assert_eq!(status.state(), VaultState::Unsealed);
        assert_eq!(status.backend(), Storage::File);
        assert_eq!(status.integrity(), Integrity::Ok);
    }
}
