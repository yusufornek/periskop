//! Rendering the small, flat JSON objects this surface answers with.
//!
//! Hand written rather than derived, and that is the point rather than an
//! omission. `tests/vault_no_plaintext.rs` fails the moment a serialisation derive
//! appears on a vault type, because a derive turns "these fields" into "whatever
//! the struct happens to hold today" and the admin projection's whole promise is
//! that it holds a closed set. Every object this module renders is built from a
//! literal list of fields a person wrote down.

/// Escapes one string for a JSON document.
///
/// Needed for exactly the values that are not drawn from a closed vocabulary: a
/// filesystem path, an identifier out of `policy.toml`, the name of a field a
/// client sent. Everything else this surface writes is an enum variant or a
/// number and cannot carry a quote.
pub fn quote(text: &str) -> String {
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

/// The top level keys of a flat JSON object, in the order they were written.
///
/// The reader the closed field set assertions use. Deliberately small: the
/// objects it reads were produced a line above by this crate, so a parser that
/// handled nesting would be answering a question nothing here asks.
#[cfg(test)]
pub fn keys_of(json: &str) -> Vec<&str> {
    let Some(body) = json
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Vec::new();
    };

    let mut keys = Vec::new();
    let mut inside_a_string = false;
    let mut escaped = false;
    // Array depth, because `entity_types` is a list and every comma inside it
    // would otherwise read as the start of another field. Without this the closed
    // field set assertion sees a dozen empty key names and fails for the wrong
    // reason, which is how it first ran.
    let mut depth = 0usize;
    let mut field_starts_at = 0usize;
    for (at, character) in body.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if inside_a_string => escaped = true,
            '"' => inside_a_string = !inside_a_string,
            '[' | '{' if !inside_a_string => depth += 1,
            ']' | '}' if !inside_a_string => depth = depth.saturating_sub(1),
            ',' if !inside_a_string && depth == 0 => {
                keys.push(key_of(&body[field_starts_at..at]));
                field_starts_at = at + 1;
            }
            _ => {}
        }
    }
    keys.push(key_of(&body[field_starts_at..]));
    keys
}

#[cfg(test)]
fn key_of(field: &str) -> &str {
    field
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or_default()
        .trim()
        .trim_matches('"')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_value_a_client_chose_cannot_break_the_document() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("line\nbreak"), r#""line\nbreak""#);
        // Escaped rather than dropped: a raw control byte makes the document
        // invalid, and a client that cannot parse a refusal cannot act on it.
        assert_eq!(quote("bell\u{7}"), r#""bell\u0007""#);
    }

    #[test]
    fn the_key_reader_sees_every_field_and_no_field_that_is_not_there() {
        assert_eq!(
            keys_of(r#"{"a":1,"b":"x,y","c":null}"#),
            vec!["a", "b", "c"]
        );
        // A comma inside a nested list or object belongs to that value, not to the
        // object being read. Without this the closed field set assertions see a
        // dozen empty names and fail for the wrong reason, which is how they first
        // ran against `entity_types`.
        assert_eq!(
            keys_of(r#"{"a":["x","y"],"b":{"c":1,"d":2},"e":3}"#),
            vec!["a", "b", "e"]
        );
        // A reader that returned an empty list would make every closed field set
        // assertion pass over any object at all.
        assert!(keys_of("not an object").is_empty());
    }
}
