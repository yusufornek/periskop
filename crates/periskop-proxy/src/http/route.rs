//! Which endpoint a request is, decided by the path alone.
//!
//! The table is `proxy/spec.md` section 2.2 plus the two path decisions in
//! `proxy-api.md`, and the reason it is a table rather than a chain of `if`s is
//! the second of those decisions. SB-4/D-22 gave each provider its own namespace
//! because both of them serve `GET /v1/models`: with Anthropic mounted under the
//! shared `/v1/*` prefix, the upstream for that request cannot be **read off the
//! path**, so the proxy would have to guess or consult a header, and either one
//! can silently send a request to the wrong provider. A route resolved from a
//! literal path is what makes that impossible rather than unlikely.
//!
//! `POST /v1/messages` is therefore not an endpoint. It is the path an operator
//! reaches for out of habit, and it gets a 404: forwarding it to Anthropic would
//! reintroduce exactly the ambiguity the namespace split removed.

use super::errors::{ProxyError, Refusal};

/// The upstream this request belongs to.
///
/// Read from the path prefix and from nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Provider {
    OpenAi,
    Anthropic,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

/// What the masking layer does with this endpoint's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Treatment {
    /// Scanned, masked, and the response un-masked on the way back.
    MaskedRoundTrip,
    /// Scanned and masked on the way up; a vector comes back and there is nothing
    /// to put back (`proxy/spec.md` section 2.2, open question 6).
    MaskedOneWay,
    /// Carries no user text: a model list. Forwarded and not scanned.
    NoUserText,
    /// Reaches the provider unmasked, and says so in three places
    /// (`proxy-api.md`, "Tool-call argümanları": the same rule covers the
    /// Responses and Assistants surfaces under
    /// `endpoint_unsupported_passthrough`).
    UnmaskedAndDeclared,
}

/// periskop's own endpoints (`proxy/spec.md` section 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Periskop {
    Health,
    /// Alias **counts** for one session. Never the aliases and never the values.
    Session,
}

/// The administrative surface (`proxy-api.md`, "periskop'a özgü uçlar").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Admin {
    Policy,
    VaultStatus,
    Metrics,
}

impl Admin {
    pub const ALL: [Self; 3] = [Self::Policy, Self::VaultStatus, Self::Metrics];

    pub const fn path(self) -> &'static str {
        match self {
            Self::Policy => "/admin/policy",
            Self::VaultStatus => "/admin/vault/status",
            Self::Metrics => "/admin/metrics",
        }
    }
}

/// A resolved endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Passthrough {
        provider: Provider,
        treatment: Treatment,
        /// The path at the provider, which is not always the path the client
        /// used: Anthropic is mounted under `/anthropic` here and answers at
        /// `/v1/...` there.
        upstream_path: String,
    },
    Admin(Admin),
    Periskop {
        endpoint: Periskop,
        /// The `{id}` of `/_periskop/session/{id}`, empty for `/_periskop/health`.
        argument: String,
    },
}

/// What resolution concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    Route(Route),
    /// A known endpoint this build does not implement: 400 and the name of what
    /// was not implemented (`proxy/spec.md` section 10, task 85's criterion).
    Unsupported(Refusal),
    /// No such path. Also the answer for `POST /v1/messages`, deliberately.
    NotFound,
    /// The path exists and this method is not one of its methods.
    MethodNotAllowed,
}

/// Endpoints this build knows about and refuses, with the name it refuses under.
///
/// Section 2.2 lists image, audio and batch inputs as out of scope for v1 and the
/// SB-3 note fixes the answer for them at **400**, separately from the Responses
/// and Assistants surfaces, which pass through and declare. Two different answers
/// to "we did not implement this", so they are two different lists.
const REFUSED: &[(&str, &str)] = &[
    ("/v1/images", "endpoint /v1/images (image input)"),
    ("/v1/audio", "endpoint /v1/audio (audio input)"),
    ("/v1/batches", "endpoint /v1/batches (batch)"),
    ("/anthropic/v1/batches", "endpoint /v1/batches (batch)"),
];

/// Endpoints that reach the provider with no masking at all, and declare it.
const DECLARED_UNMASKED: &[(&str, Provider)] = &[
    ("/v1/responses", Provider::OpenAi),
    ("/v1/assistants", Provider::OpenAi),
    ("/v1/threads", Provider::OpenAi),
];

/// Resolves one request line.
///
/// `path` is the path with the query string already removed; the query is carried
/// separately because it belongs to the upstream URL rather than to the routing
/// decision.
pub fn resolve(method: &str, path: &str) -> Resolved {
    let path = normalise(path);

    if let Some(resolved) = periskop_route(method, &path) {
        return resolved;
    }
    if let Some(resolved) = admin_route(method, &path) {
        return resolved;
    }

    // `POST /v1/messages` before anything else that could match it. The contract
    // sentence is "geçerli bir uç değildir; bu yola gelen istek 404 alır ve
    // sessizce Anthropic'e yönlendirilmez", and a later rule that happened to
    // catch it would be a silent redirect by another route.
    if path == "/v1/messages" {
        return Resolved::NotFound;
    }

    for (prefix, name) in REFUSED {
        if path == *prefix || path.starts_with(&format!("{prefix}/")) {
            return Resolved::Unsupported(Refusal::new(
                ProxyError::EndpointUnsupported,
                format!("{name} is not implemented in this build"),
            ));
        }
    }

    for (prefix, provider) in DECLARED_UNMASKED {
        if path == *prefix || path.starts_with(&format!("{prefix}/")) {
            return Resolved::Route(Route::Passthrough {
                provider: *provider,
                treatment: Treatment::UnmaskedAndDeclared,
                upstream_path: path.clone(),
            });
        }
    }

    passthrough_route(method, &path)
}

fn periskop_route(method: &str, path: &str) -> Option<Resolved> {
    if path == "/_periskop/health" {
        return Some(if method == "GET" {
            Resolved::Route(Route::Periskop {
                endpoint: Periskop::Health,
                argument: String::new(),
            })
        } else {
            Resolved::MethodNotAllowed
        });
    }
    let id = path.strip_prefix("/_periskop/session/")?;
    Some(if method != "GET" {
        Resolved::MethodNotAllowed
    } else if id.is_empty() || id.contains('/') {
        Resolved::NotFound
    } else {
        Resolved::Route(Route::Periskop {
            endpoint: Periskop::Session,
            argument: id.to_owned(),
        })
    })
}

/// The administrative surface, and the reason it is read only.
///
/// Every method other than `GET` on an admin path is refused here rather than
/// falling through to a handler, because "there is no policy write endpoint"
/// (`proxy-api.md`, "Yapılandırma ve politika değişikliği") is a property of this
/// function: a write endpoint would have to be a new arm, and adding one fails
/// `the_admin_surface_answers_no_method_but_get`.
fn admin_route(method: &str, path: &str) -> Option<Resolved> {
    let endpoint = Admin::ALL.into_iter().find(|admin| admin.path() == path);
    match (endpoint, path.starts_with("/admin/")) {
        (Some(endpoint), _) if method == "GET" => Some(Resolved::Route(Route::Admin(endpoint))),
        (Some(_), _) => Some(Resolved::MethodNotAllowed),
        (None, true) => Some(Resolved::NotFound),
        (None, false) => None,
    }
}

fn passthrough_route(method: &str, path: &str) -> Resolved {
    let table: &[(&str, &str, Provider, Treatment, &str)] = &[
        (
            "POST",
            "/v1/chat/completions",
            Provider::OpenAi,
            Treatment::MaskedRoundTrip,
            "/v1/chat/completions",
        ),
        (
            "POST",
            "/v1/embeddings",
            Provider::OpenAi,
            Treatment::MaskedOneWay,
            "/v1/embeddings",
        ),
        (
            "GET",
            "/v1/models",
            Provider::OpenAi,
            Treatment::NoUserText,
            "/v1/models",
        ),
        (
            "POST",
            "/anthropic/v1/messages",
            Provider::Anthropic,
            Treatment::MaskedRoundTrip,
            "/v1/messages",
        ),
        (
            "GET",
            "/anthropic/v1/models",
            Provider::Anthropic,
            Treatment::NoUserText,
            "/v1/models",
        ),
    ];

    let mut path_exists = false;
    for (verb, client_path, provider, treatment, upstream_path) in table {
        if *client_path != path {
            continue;
        }
        path_exists = true;
        if *verb == method {
            return Resolved::Route(Route::Passthrough {
                provider: *provider,
                treatment: *treatment,
                upstream_path: (*upstream_path).to_owned(),
            });
        }
    }

    if path_exists {
        Resolved::MethodNotAllowed
    } else {
        Resolved::NotFound
    }
}

/// Strips a trailing slash so that `/admin/policy/` is the same endpoint as
/// `/admin/policy`, and leaves everything else exactly as it arrived.
///
/// No percent decoding and no `..` collapsing on purpose: this function does not
/// build a filesystem path or an upstream URL out of the result, it compares it
/// against literals. A decoder here would let `%2e%2e` and `/admin/policy` reach
/// the same arm through two different strings, which is how path confusion gets
/// in. `passthrough` builds the upstream URL from the route's own
/// `upstream_path`, which is a literal from the table above.
fn normalise(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn route(method: &str, path: &str) -> Route {
        match resolve(method, path) {
            Resolved::Route(route) => route,
            other => panic!("{method} {path} did not resolve: {other:?}"),
        }
    }

    #[test]
    fn the_five_passthrough_endpoints_are_the_ones_the_spec_lists() {
        assert_eq!(
            route("POST", "/v1/chat/completions"),
            Route::Passthrough {
                provider: Provider::OpenAi,
                treatment: Treatment::MaskedRoundTrip,
                upstream_path: "/v1/chat/completions".to_owned(),
            }
        );
        assert_eq!(
            route("POST", "/v1/embeddings"),
            Route::Passthrough {
                provider: Provider::OpenAi,
                treatment: Treatment::MaskedOneWay,
                upstream_path: "/v1/embeddings".to_owned(),
            }
        );
        assert_eq!(
            route("GET", "/v1/models"),
            Route::Passthrough {
                provider: Provider::OpenAi,
                treatment: Treatment::NoUserText,
                upstream_path: "/v1/models".to_owned(),
            }
        );
    }

    /// The namespace split, and the request it exists for.
    ///
    /// Both providers answer `GET /v1/models`. If the two resolved to the same
    /// upstream, one of the two would be silently answered by the wrong provider,
    /// which is the failure SB-4 traded a longer `base_url` to remove.
    #[test]
    fn each_provider_owns_its_own_models_endpoint() {
        let openai = route("GET", "/v1/models");
        let anthropic = route("GET", "/anthropic/v1/models");
        assert_ne!(openai, anthropic);

        let Route::Passthrough {
            provider,
            upstream_path,
            ..
        } = anthropic
        else {
            panic!("not a passthrough")
        };
        assert_eq!(provider, Provider::Anthropic);
        // Mounted under `/anthropic` here, answered at `/v1/models` there.
        assert_eq!(upstream_path, "/v1/models");
    }

    #[test]
    fn the_anthropic_messages_path_is_rewritten_for_the_upstream() {
        assert_eq!(
            route("POST", "/anthropic/v1/messages"),
            Route::Passthrough {
                provider: Provider::Anthropic,
                treatment: Treatment::MaskedRoundTrip,
                upstream_path: "/v1/messages".to_owned(),
            }
        );
    }

    /// `proxy-api.md`: "`/v1/messages` **geçerli bir uç değildir**; bu yola gelen
    /// istek 404 alır ve sessizce Anthropic'e yönlendirilmez."
    #[test]
    fn the_shared_namespace_messages_path_is_not_an_endpoint_and_is_not_forwarded() {
        for method in ["POST", "GET"] {
            assert_eq!(resolve(method, "/v1/messages"), Resolved::NotFound);
        }
        // The assertion that matters is not the status but the absence of a
        // route: a 404 that still forwarded would be a redirect with a misleading
        // status on it.
        assert!(!matches!(
            resolve("POST", "/v1/messages"),
            Resolved::Route(_)
        ));
    }

    #[test]
    fn an_endpoint_this_build_does_not_implement_is_a_400_that_names_it() {
        for (path, expected) in [
            ("/v1/audio/transcriptions", "/v1/audio"),
            ("/v1/images/generations", "/v1/images"),
            ("/v1/batches", "/v1/batches"),
        ] {
            let Resolved::Unsupported(refusal) = resolve("POST", path) else {
                panic!("{path} was not refused");
            };
            assert_eq!(refusal.status(), 400);
            assert_eq!(refusal.error(), ProxyError::EndpointUnsupported);
            assert!(
                refusal.detail().contains(expected),
                "{path}: the refusal does not say which endpoint: {}",
                refusal.detail()
            );
        }
    }

    #[test]
    fn the_responses_surface_passes_through_and_is_marked_for_declaration() {
        let Route::Passthrough { treatment, .. } = route("POST", "/v1/responses") else {
            panic!("not a passthrough")
        };
        // Not `MaskedRoundTrip`. The roadmap's phase boundary item 4 puts this
        // surface outside masking entirely, and the price is a declaration rather
        // than a silence.
        assert_eq!(treatment, Treatment::UnmaskedAndDeclared);
    }

    #[test]
    fn the_admin_surface_answers_no_method_but_get() {
        for admin in Admin::ALL {
            assert_eq!(
                resolve("GET", admin.path()),
                Resolved::Route(Route::Admin(admin))
            );
            // The claim task 87 asks to pin: there is no policy write endpoint.
            // Asserted over every method a client could try rather than over
            // `POST` alone, because a write endpoint added as `PUT` would leave a
            // `POST`-only test green.
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                assert_eq!(
                    resolve(method, admin.path()),
                    Resolved::MethodNotAllowed,
                    "{method} {}",
                    admin.path()
                );
            }
        }
        // And nothing else under `/admin/` resolves at all, so a handler added
        // without a route table entry is unreachable rather than unlisted.
        for path in [
            "/admin",
            "/admin/policy/write",
            "/admin/vault",
            "/admin/anything",
        ] {
            assert_eq!(resolve("POST", path), Resolved::NotFound, "{path}");
        }
    }

    #[test]
    fn the_admin_route_table_holds_three_read_endpoints_and_no_fourth() {
        let paths: Vec<&str> = Admin::ALL.into_iter().map(Admin::path).collect();
        assert_eq!(
            paths,
            vec!["/admin/policy", "/admin/vault/status", "/admin/metrics"]
        );
    }

    #[test]
    fn periskop_s_own_endpoints_carry_their_argument() {
        assert_eq!(
            route("GET", "/_periskop/health"),
            Route::Periskop {
                endpoint: Periskop::Health,
                argument: String::new(),
            }
        );
        assert_eq!(
            route("GET", "/_periskop/session/abc123"),
            Route::Periskop {
                endpoint: Periskop::Session,
                argument: "abc123".to_owned(),
            }
        );
        assert_eq!(resolve("GET", "/_periskop/session/"), Resolved::NotFound);
        assert_eq!(
            resolve("POST", "/_periskop/health"),
            Resolved::MethodNotAllowed
        );
    }

    #[test]
    fn a_trailing_slash_is_the_same_endpoint_and_an_unknown_path_is_not_one() {
        assert_eq!(
            resolve("GET", "/admin/policy/"),
            Resolved::Route(Route::Admin(Admin::Policy))
        );
        for path in ["/", "/v1", "/v1/chat", "/anthropic", "/completions"] {
            assert_eq!(resolve("GET", path), Resolved::NotFound, "{path}");
        }
    }

    #[test]
    fn a_known_path_with_the_wrong_method_is_not_a_masked_route() {
        // A `GET /v1/chat/completions` that fell through to the passthrough arm
        // would forward a request with no body, which is a request nothing masked.
        assert_eq!(
            resolve("GET", "/v1/chat/completions"),
            Resolved::MethodNotAllowed
        );
        assert_eq!(resolve("DELETE", "/v1/models"), Resolved::MethodNotAllowed);
    }
}
