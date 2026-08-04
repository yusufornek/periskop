//! Which machine this build is running on.
//!
//! A value rather than a `cfg!` sprinkled through the load path. The difference
//! matters: with a value, the Linux branch of every decision is exercised by the
//! test suite on the macOS machine this workspace is developed on, and the
//! non Linux branch is exercised on Linux in continuous integration. With
//! `cfg!` at each decision point, each machine would only ever run half the
//! logic and the other half would be checked by reading it.
//!
//! [`HostPlatform::current`] is the one place the compile time answer is turned
//! into a value, and it is the only thing in this module that a given build
//! cannot fully exercise.

/// The platform class this loader recognises.
///
/// Two values, not a platform matrix. ADR-008 fixes pcap as the mechanism for
/// macOS and Windows, and its D-21e revision keeps both out of v1; a variant for
/// either would suggest this crate has something to offer them, and it does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HostPlatform {
    /// Linux, where eBPF exists.
    Linux,
    /// Anything else. The default, because assuming the capable platform is the
    /// wrong direction to guess in: it would let a build claim an observation it
    /// has no mechanism for.
    #[default]
    Other,
}

impl HostPlatform {
    /// What this build was compiled for.
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }

    /// Whether an eBPF load could be attempted here at all.
    pub fn supports_ebpf(self) -> bool {
        matches!(self, Self::Linux)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_linux_can_host_the_programs() {
        assert!(HostPlatform::Linux.supports_ebpf());
        assert!(!HostPlatform::Other.supports_ebpf());
    }

    #[test]
    fn an_unrecognised_platform_defaults_to_the_one_with_no_mechanism() {
        // Defaulting the other way would let a caller that forgot to ask get a
        // load attempt on a machine with nothing to load into.
        assert_eq!(HostPlatform::default(), HostPlatform::Other);
    }

    #[test]
    fn this_build_agrees_with_the_target_it_was_compiled_for() {
        // Runs on whatever machine this is, and is the only assertion here that
        // sees a different answer on the development machine than in Linux
        // continuous integration.
        let expected = if cfg!(target_os = "linux") {
            HostPlatform::Linux
        } else {
            HostPlatform::Other
        };
        assert_eq!(HostPlatform::current(), expected);
    }
}
