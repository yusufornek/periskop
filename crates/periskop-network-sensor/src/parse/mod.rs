//! The two parses the `tc` helper is allowed to perform, and nothing else.
//!
//! ADR-008 admits a `tc` (clsact) program into the sensor for one reason: the
//! kprobe hooks that carry process context cannot see packet payload, and both
//! classification signals live in payload. The ADR then draws the boundary
//! tightly, and this module is where that boundary is code rather than prose.
//! It contains exactly two parsers, [`dns::parse_response`] and
//! [`tls::parse_client_hello`], and each returns a small set of facts. No
//! function here returns bytes, so nothing downstream of this module can
//! receive a payload even by accident. That is the same technique the `Flow`
//! record uses to guarantee it has no content field, applied one layer earlier.
//!
//! What is deliberately absent is as much of the design as what is present:
//!
//! - No general packet reassembly. Each parser sees one bounded sample.
//! - No HTTP body reading, no header extraction beyond nothing at all.
//! - No packet modification. The `tc` program is a reader; the sensor is
//!   passive by principle and the ADR requires `TC_ACT_OK` unconditionally.
//! - No TLS decryption, no key material, no session state.
//!
//! Both parsers are ordinary functions over `&[u8]` with no kernel and no clock
//! in them. The eBPF side of this milestone cannot run in continuous
//! integration, so every decision that changes what a report says about a
//! destination was pushed down here, where it runs everywhere and is tested
//! against malformed, truncated and hostile input rather than against a kernel
//! that happens to be handy.

mod cursor;
pub mod dns;
pub mod tls;
