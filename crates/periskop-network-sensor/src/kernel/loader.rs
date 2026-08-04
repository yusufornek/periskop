//! The one place a kernel object would be opened, and why it is empty here.
//!
//! Loading an eBPF program is a `bpf(2)` call, a set of file descriptors and a
//! memory mapped ring buffer. In Rust that is a foreign function boundary, and
//! a foreign function boundary is `unsafe`. This workspace sets
//! `unsafe_code = "forbid"` (ADR-002), and `forbid` is not a level a crate can
//! lift with an `allow`; it can only be lifted where the lint is configured.
//! ADR-002 anticipated this and named the eBPF loader as one of three crates
//! allowed the exception, but it did not say through which mechanism.
//!
//! ADR-014 answers that: the exception is granted to a **separate crate behind
//! a non default feature**, never to this crate, so that the shipped default
//! build of the sensor contains no `unsafe` at all and everything in this file's
//! neighbourhood stays inside the workspace lint. This module is the seam that
//! decision produces. It is deliberately the smallest thing that can be: a
//! platform check and an honest refusal.
//!
//! Until that crate exists, an attach on Linux reports `loader_not_built`. That
//! is a stated cause with a remedy, not silence, and it is spelled in the same
//! vocabulary a permission failure uses so a report cannot present "nothing was
//! observed because nothing was loaded" as a clean network.
//!
//! Off Linux the answer is `unsupported_platform`. ADR-008 fixes pcap as the
//! mechanism for macOS and Windows and its D-21e revision keeps those platforms
//! out of v1; claiming anything else here would promise observation no code in
//! this workspace performs.

use super::attach::AttachPlan;
use super::event::KernelBatch;
use super::KernelEvents;
use crate::privilege::SensorUnavailable;

/// The kernel side of the sensor on the machine this build runs on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PlatformKernel;

impl KernelEvents for PlatformKernel {
    fn attach(&mut self, _plan: &AttachPlan) -> Result<(), SensorUnavailable> {
        if cfg!(target_os = "linux") {
            Err(SensorUnavailable::LoaderNotBuilt)
        } else {
            Err(SensorUnavailable::UnsupportedPlatform)
        }
    }

    fn poll(&mut self) -> KernelBatch {
        // Reachable only if a caller ignored the attach failure. An empty batch
        // is correct here and nowhere else: nothing was attached, so nothing
        // was seen, and the sensor states that through the attach error rather
        // than by handing back a plausible looking empty result.
        KernelBatch::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::kernel::attach;
    use crate::privilege::Grant;

    fn plan() -> AttachPlan {
        attach::plan(&Grant {
            tc_available: true,
            elevated_as_root: false,
        })
    }

    #[test]
    fn the_shipped_loader_refuses_in_a_vocabulary_a_report_can_carry() {
        // Runs on whatever machine this is. The point is that there is always a
        // stated cause, never an attach that quietly succeeds having loaded
        // nothing.
        let refusal = PlatformKernel.attach(&plan()).unwrap_err();
        let expected = if cfg!(target_os = "linux") {
            SensorUnavailable::LoaderNotBuilt
        } else {
            SensorUnavailable::UnsupportedPlatform
        };
        assert_eq!(refusal, expected);
        assert!(!refusal.as_str().is_empty());
    }

    #[test]
    fn off_linux_the_cause_is_the_platform_and_not_a_missing_build() {
        // The two remedies are different: one is "build the loader", the other
        // is "there is nothing to build for this machine in v1". An operator
        // sent to the wrong one wastes the time the report was meant to save.
        if cfg!(target_os = "linux") {
            return;
        }
        assert_eq!(
            PlatformKernel.attach(&plan()),
            Err(SensorUnavailable::UnsupportedPlatform)
        );
    }

    #[test]
    fn a_kernel_that_never_attached_reports_no_events_and_no_losses() {
        let batch = PlatformKernel.poll();
        assert!(batch.events.is_empty());
        assert_eq!(batch.dropped, 0);
    }
}
