//! What the kernel is holding on this machine's behalf, once a load succeeded.
//!
//! Compiled only when there is a kernel side object to load
//! (`periskop_kernel_object`, set by `build.rs`) and only on Linux. Everywhere
//! else this module does not exist and [`crate::EbpfLoader`] reports
//! `loader_not_built`, which is the truth about that binary rather than a
//! placeholder.
//!
//! # No `unsafe` here, which was not the expectation
//!
//! ADR-014 assumed the loader's foreign function surface would be the loading
//! and the ring buffer. It is not: `aya` exposes both through a safe API, so the
//! whole of this file is safe Rust and the crate's exception (`syscall`) is
//! three functions with no equivalent in `std`. The narrower grant is worth
//! stating because it is the one thing about this crate a reviewer would
//! otherwise have to take on trust.
//!
//! # What holding the [`Ebpf`] value means
//!
//! Everything the kernel accepted stays attached for as long as this value
//! lives, and dropping it detaches every program and closes every descriptor.
//! There is therefore exactly one place a sensor stops observing, and it is the
//! same place it stops existing.

use aya::maps::{Array, MapData, RingBuf};
use aya::programs::KProbe;
use aya::Ebpf;

use crate::hook::Hook;
use crate::object::{self, Attachment};

/// The wall clock bucket the kernel program rounds a start time down to.
///
/// Sixty seconds. The value lives here rather than in the kernel object because
/// it is a reporting decision, and reporting decisions belong on the side that
/// runs in continuous integration (ADR-014 §3).
const BUCKET_SECS: u64 = 60;

const CONFIG_MAP: &str = "CONFIG";
const EVENTS_MAP: &str = "EVENTS";
const DROPPED_MAP: &str = "DROPPED";

/// The two slots of `DROPPED`, in the order the kernel object declares them.
///
/// Kept apart rather than summed, because the two losses have different
/// remedies: a ring buffer to enlarge and an in flight map to enlarge. A single
/// number would let either present itself as the other.
const DROPPED_RING_FRAMES: u32 = 0;
const DROPPED_UNTRACKED_CALLS: u32 = 1;

const CONFIG_WALL_OFFSET_NS: u32 = 0;
const CONFIG_ATTACHED_AT_NS: u32 = 1;
const CONFIG_BUCKET_SECS: u32 = 2;

/// Why a load stopped, in enough detail for the caller to pick a cause.
///
/// Kept separate from [`crate::LoaderUnavailable`] so that the mapping from "the
/// kernel refused this program" to "what a report says" happens in one place and
/// is visible there.
#[derive(Debug)]
pub enum OpenError {
    /// The object could not be parsed, relocated or loaded. On a machine that
    /// passed the capability and BTF checks this is the verifier, and it is the
    /// one failure that means the program is wrong rather than the machine.
    Rejected(String),
    /// A clock reading the kernel would not give.
    ClockUnreadable,
    /// A map the object is supposed to declare was not in it.
    MapMissing(&'static str),
    /// A program the hook table names was not in the object. Reported rather
    /// than skipped: attaching what is present and dropping the rest would leave
    /// the sensor believing it observes something it does not.
    ProgramMissing(&'static str),
}

/// The kernel objects one attach produced.
pub struct Attached {
    /// Holds every program and every link. Dropping it detaches them.
    _programs: Ebpf,
    events: RingBuf<MapData>,
    dropped: Array<MapData, u64>,
}

impl Attached {
    /// Loads the object, tells it what time it is, and attaches the requested
    /// hooks.
    ///
    /// The clock is written before anything is attached, so no program can fire
    /// against an offset nobody set. A record stamped from slot zero of an empty
    /// map would carry a bucket in 1970, which is a wrong answer that looks like
    /// a right one.
    pub fn open(hooks: &[Hook], now_monotonic_ns: u64, epoch_ns: u64) -> Result<Self, OpenError> {
        let mut programs =
            Ebpf::load(object::BYTES).map_err(|error| OpenError::Rejected(error.to_string()))?;

        let wall_offset_ns = epoch_ns
            .checked_sub(now_monotonic_ns)
            .ok_or(OpenError::ClockUnreadable)?;
        write_config(&mut programs, wall_offset_ns, now_monotonic_ns)?;

        // Loaded once each, attached possibly twice: the connect pair serves both
        // the IPv4 and the IPv6 entry point, and `aya` will not load one program
        // twice.
        let mut loaded: Vec<&'static str> = Vec::new();
        for hook in hooks {
            for attachment in object::attachments_for(*hook) {
                attach_one(&mut programs, attachment, &mut loaded)?;
            }
        }

        let events = programs
            .take_map(EVENTS_MAP)
            .ok_or(OpenError::MapMissing(EVENTS_MAP))
            .and_then(|map| {
                RingBuf::try_from(map).map_err(|_| OpenError::MapMissing(EVENTS_MAP))
            })?;
        let dropped = programs
            .take_map(DROPPED_MAP)
            .ok_or(OpenError::MapMissing(DROPPED_MAP))
            .and_then(|map| Array::try_from(map).map_err(|_| OpenError::MapMissing(DROPPED_MAP)))?;

        Ok(Self {
            _programs: programs,
            events,
            dropped,
        })
    }

    /// Everything the ring buffer holds right now, as raw frames.
    ///
    /// Non blocking and bounded by what is already in the buffer, because the
    /// sensor polls rather than waits: a read that blocked would make the sensor
    /// depend on the machine producing traffic in order to shut down.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(item) = self.events.next() {
            frames.push(item.to_vec());
        }
        frames
    }

    /// Frames the kernel program could not fit into the ring buffer, when the
    /// kernel will say how many.
    ///
    /// Counted on the kernel side, because that is the only side that sees the
    /// reservation fail. A sensor that reported no losses because it had no way
    /// to count them would be understating what it missed.
    ///
    /// `None` is that case and it is deliberately not a zero. A map lookup that
    /// the kernel refuses says nothing about how many frames were lost, and the
    /// one answer it must never be turned into is the answer a healthy busy
    /// machine gives. Reading `unwrap_or(0)` here made an unreadable counter
    /// indistinguishable from a run that lost nothing, which is the confusion
    /// between "I do not know" and "there is none" this whole product argues
    /// against.
    pub fn dropped(&self) -> Option<u64> {
        self.dropped.get(&DROPPED_RING_FRAMES, 0).ok()
    }

    /// Calls the kernel program could not track, when the kernel will say how
    /// many.
    ///
    /// The second loss this object can see, and the one the coverage statement
    /// used to have no word for. An entry probe that cannot stash its socket in
    /// the in flight map produces no record at all, so the loss never reaches
    /// the ring buffer and the counter above cannot see it: a busy machine
    /// reported `dropped_events: 0` while flows went unobserved, and an operator
    /// reading that number read a complete capture.
    ///
    /// `None` for the same reason [`Self::dropped`] uses it, and a floor rather
    /// than a count even when it is `Some`: one connection missed on several
    /// calls increments this several times, and nothing on either side of the
    /// seam can collapse them.
    pub fn untracked_calls(&self) -> Option<u64> {
        self.dropped.get(&DROPPED_UNTRACKED_CALLS, 0).ok()
    }
}

fn write_config(
    programs: &mut Ebpf,
    wall_offset_ns: u64,
    attached_at_ns: u64,
) -> Result<(), OpenError> {
    let map = programs
        .map_mut(CONFIG_MAP)
        .ok_or(OpenError::MapMissing(CONFIG_MAP))?;
    let mut config: Array<_, u64> =
        Array::try_from(map).map_err(|_| OpenError::MapMissing(CONFIG_MAP))?;
    for (slot, value) in [
        (CONFIG_WALL_OFFSET_NS, wall_offset_ns),
        (CONFIG_ATTACHED_AT_NS, attached_at_ns),
        (CONFIG_BUCKET_SECS, BUCKET_SECS),
    ] {
        config
            .set(slot, value, 0)
            .map_err(|error| OpenError::Rejected(error.to_string()))?;
    }
    Ok(())
}

fn attach_one(
    programs: &mut Ebpf,
    attachment: &Attachment,
    loaded: &mut Vec<&'static str>,
) -> Result<(), OpenError> {
    let program = programs
        .program_mut(attachment.program)
        .ok_or(OpenError::ProgramMissing(attachment.program))?;
    let probe: &mut KProbe = program
        .try_into()
        .map_err(|error: aya::programs::ProgramError| OpenError::Rejected(error.to_string()))?;
    if !loaded.contains(&attachment.program) {
        probe
            .load()
            .map_err(|error| OpenError::Rejected(error.to_string()))?;
        loaded.push(attachment.program);
    }
    probe
        .attach(attachment.function, 0)
        .map(|_| ())
        .map_err(|error| OpenError::Rejected(error.to_string()))
}
