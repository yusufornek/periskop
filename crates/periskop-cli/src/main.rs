//! periskop command line interface.
//!
//! Exit codes are a contract, not a detail. Continuous integration reads them, so
//! they are mapped explicitly here rather than falling out of whatever the last
//! expression returned.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use periskop_cli::clock::now_rfc3339;
use periskop_cli::hook::{self, Ambient, HookError, HookRequest, Language};
use periskop_cli::{policy, proxy, render, rpc, scan, sensor};

// The two halves of report signing. Modules of the binary rather than of the
// library, because they are command surfaces: argument parsing, file paths and
// exit codes. Everything that decides what a signature means lives in
// `periskop-report`, where a second front end can reach it without going through
// a process.
mod sign;
mod verify;

/// Exit codes, fixed by the command line contract.
mod exit {
    /// Scan completed and the policy passed.
    pub const PASS: u8 = 0;
    /// Scan completed and the policy failed.
    pub const FAIL: u8 = 1;
    /// The scan itself could not run.
    pub const ERROR: u8 = 2;
    /// The scan ran but saw too little to stand behind the result.
    pub const INSUFFICIENT_COVERAGE: u8 = 3;
}

#[derive(Parser)]
#[command(
    name = "periskop",
    version,
    about = "Find out where your code sends data to LLM providers, and prove the answer."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a project for calls that send data to a model provider.
    Scan {
        /// Project directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Emit the full report as JSON instead of a summary.
        #[arg(long)]
        json: bool,

        /// Directory holding detector rules.
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,

        /// Directory the runtime hook wrote its event stream into.
        ///
        /// Optional, and the report says which it was. Without it the scan reads
        /// code alone and declares itself static_only; with it the code side and
        /// the observed calls are reconciled and their disagreements become
        /// findings. Also read from PERISKOP_EVENT_DIR, which is what `hook
        /// install` prints, so a hooked project does not have to repeat the path
        /// on every run.
        #[arg(long, value_name = "DIR")]
        events: Option<PathBuf>,

        /// Directory holding the network sensor's flow records.
        ///
        /// The third source, and the only one that can see a connection no code
        /// and no hooked call explains. Optional like the second: without it the
        /// scan reports exactly what it reported before, and the report never
        /// says `full`, because two sources may not make a three source claim.
        /// Also read from PERISKOP_FLOW_DIR.
        #[arg(long, value_name = "DIR")]
        flows: Option<PathBuf>,

        /// Policy file to decide this run under.
        ///
        /// Defaults to `periskop-policy.toml` in the scanned project's root, and
        /// a project with no such file runs on the engine's own thresholds. The
        /// one threshold that has no engine default is the volume band: without
        /// a policy declaring it, `volume_anomaly` is reported as suppressed
        /// rather than derived against an invented number.
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,

        /// Fail when the share of unreadable files exceeds this many basis points.
        #[arg(long, value_name = "BASIS_POINTS")]
        max_unparsed_ratio: Option<u64>,
    },

    /// Watch this machine's outbound connections and write what left it.
    ///
    /// The third source, and the only one that can see a connection no code and
    /// no hooked call explains. Writes records `periskop scan --flows` reads.
    /// Needs `CAP_BPF` and `CAP_PERFMON` on a Linux host with BTF; on any other
    /// machine it writes an empty record set, says why, and exits non zero
    /// rather than failing or pretending the machine was quiet.
    Sensor(SensorArgs),

    /// Mask what leaves for a model provider, and put it back in the answer.
    ///
    /// Today it opens the encrypted vault and stops, because the request path is
    /// not built yet. It ends non zero and says so rather than listening and
    /// passing traffic through unmasked, which is the one thing a proxy with this
    /// job may never do. The passphrase is read from standard input.
    Proxy(ProxyArgs),

    /// Serve the engine over JSON-RPC on stdin and stdout.
    ///
    /// Used by the MCP server, which stays a thin client so that detection lives
    /// in one place rather than being reimplemented in a second language.
    ServeRpc {
        /// Directory holding detector rules.
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,
    },

    /// Install the runtime hook that records what the code actually did.
    ///
    /// Optional. A scan reads code and reports the same thing with or without a
    /// hook; what a hook adds is the second source reconciliation compares the
    /// first against.
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },

    /// Sign a report, producing a detached signature envelope beside it.
    ///
    /// The signature says the report came from the named key unaltered. It says
    /// nothing about whether the scan was complete or correct: that is what the
    /// report's own coverage block is for.
    Sign(sign::SignArgs),

    /// Check a detached signature over a report.
    ///
    /// Exits non zero for every outcome but one. An unsigned report, a broken
    /// signature, a key that was not named and an envelope that fails its schema
    /// are all refusals, and none of them can be mistaken for a pass.
    Verify(verify::VerifyArgs),

    /// Ed25519 key material for report signing.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Args)]
struct SensorArgs {
    /// Directory the flow records are written into.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,

    /// Executable path or process name belonging to the codebase under scan.
    ///
    /// Repeatable. Without at least one, nothing can be attributed to the
    /// project, every attributed flow lands in `out_of_scope_process`, and no
    /// unmatched traffic finding can be derived from the pass. That is a
    /// legitimate way to run the sensor and the status says what it costs, so it
    /// is not made a required flag.
    #[arg(long = "scope-process", value_name = "EXE_OR_COMM")]
    scope_processes: Vec<String>,

    /// Destination host the operator declares benign. Repeatable, exact match.
    #[arg(long = "benign-host", value_name = "HOST")]
    benign_hosts: Vec<String>,

    /// Machine identity to stamp records with. Hashed before it is written.
    #[arg(long, value_name = "ID")]
    host_id: Option<String>,
}

#[derive(Args)]
struct ProxyArgs {
    /// Argon2id profile the vault key is derived under.
    ///
    /// `default` is the shipped strength (256 MiB). `ci` lowers it to 64 MiB for
    /// machines that cannot spare the memory, and saying so is not free: the run
    /// prints a note that the vault is cheaper to attack offline.
    #[arg(long, value_name = "default|ci")]
    vault_profile: Option<String>,

    /// Policy file the proxy serves under. Defaults to `policy.toml` here.
    ///
    /// There is no built-in fallback: a masking proxy running under rules nobody
    /// wrote is what this component exists to argue against, so a policy that is
    /// missing or unloadable stops the command.
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Address to listen on. Defaults to `127.0.0.1:8787`.
    ///
    /// A reachable address is refused unless `--allow-external-interface` is also
    /// given: this build has no per-caller authorisation on the proxy surface.
    #[arg(long, value_name = "HOST:PORT")]
    listen: Option<String>,

    /// Accept a bind address that is reachable from outside this host.
    ///
    /// Behind the vault keys and the alias table there is no authorisation at
    /// all, so this hands any host that can route here another user's alias
    /// scope. It exists because some deployments really mean it.
    #[arg(long)]
    allow_external_interface: bool,

    /// Send a provider's traffic somewhere other than its published endpoint.
    ///
    /// `--upstream openai=https://gateway.internal.example/v1`. Repeatable. The
    /// host is added to the connect allow list, because writing it here is as
    /// explicit as an allow list entry gets, and the run says so on start-up.
    #[arg(long, value_name = "PROVIDER=URL")]
    upstream: Vec<String>,
}

#[derive(Subcommand)]
enum KeyCommand {
    // Unresolved against `docs/02-components/reporting/spec.md` §5, which says
    // periskop does not generate keys. Recorded with the quote and three ways
    // out in ADR-015 §7.1 rather than left for somebody to discover. The two
    // commands beside it, `sign --key` and `verify --public-key`, do match that
    // spec: it names a key file as a supported source.
    /// Generate a signing key pair.
    ///
    /// Writes to the two paths given and to nowhere else. There is no default
    /// location: a private key belongs where its owner decided to put it.
    Generate(sign::KeyGenerateArgs),
}

#[derive(Subcommand)]
enum HookCommand {
    /// Place the hook where the interpreter will find it.
    Install(HookInstallArgs),
}

#[derive(Args)]
struct HookInstallArgs {
    /// Runtime to install the hook for.
    #[arg(long, value_name = "python|node")]
    language: Language,

    /// Print the environment variables and change nothing on disk.
    #[arg(long)]
    print_env: bool,

    /// Directory the hook is copied into. Required unless --print-env.
    #[arg(long, value_name = "DIR")]
    target: Option<PathBuf>,

    /// Directory holding the hook sources.
    #[arg(long, value_name = "DIR")]
    source: Option<PathBuf>,

    /// Directory the hook writes its event stream into.
    #[arg(long, value_name = "DIR")]
    event_dir: Option<PathBuf>,

    /// Replace an existing installation instead of stopping.
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            json,
            rules,
            events,
            flows,
            policy,
            max_unparsed_ratio,
        } => run_scan(ScanArgs {
            path,
            json,
            rules,
            events,
            flows,
            policy,
            max_unparsed_ratio,
        }),
        Command::Sensor(args) => run_sensor(&args),
        Command::Proxy(args) => run_proxy(&args),
        Command::ServeRpc { rules } => run_serve_rpc(rules),
        Command::Hook {
            command: HookCommand::Install(args),
        } => run_hook_install(&args),
        Command::Sign(args) => sign::run(&args),
        Command::Verify(args) => verify::run(&args),
        Command::Key {
            command: KeyCommand::Generate(args),
        } => sign::run_key_generate(&args),
    }
}

/// Installs a runtime hook, or says what installing one by hand would need.
///
/// Both paths end by printing the environment variables to stdout, because an
/// installation the application is not pointed at records nothing, and a command
/// that stops one step short of working is a command that gets reported as
/// broken.
fn run_hook_install(args: &HookInstallArgs) -> ExitCode {
    let source_root = args
        .source
        .clone()
        .unwrap_or_else(hook::default_source_root);
    let event_dir = args
        .event_dir
        .clone()
        .unwrap_or_else(hook::default_event_dir);

    let request = HookRequest {
        language: args.language,
        source_root: &source_root,
        target: args.target.as_deref(),
        event_dir: &event_dir,
        force: args.force,
    };

    if !args.print_env {
        match hook::install(&request) {
            Ok(installed) => {
                let verb = if installed.replaced {
                    "replaced"
                } else {
                    "installed"
                };
                for path in &installed.written {
                    eprintln!("periskop: {verb} {}", path.display());
                }
            }
            Err(e) => return report_hook_error(&e),
        }
    }

    match hook::env_vars(&request, &Ambient::from_env()) {
        Ok(vars) => {
            for var in vars {
                println!("{var}");
            }
            eprintln!("{}", hook::env_notes(args.language));
            ExitCode::from(exit::PASS)
        }
        Err(e) => report_hook_error(&e),
    }
}

/// Opens the masking vault and serves the proxy until the process ends.
///
/// Every refusal exits non zero and nothing is forwarded on the way out: this
/// command either serves under a policy that loaded and a vault that opened, or
/// it serves nothing at all (`proxy/spec.md` section 10).
fn run_proxy(args: &ProxyArgs) -> ExitCode {
    let stdin = std::io::stdin();
    let outcome = proxy::prepare(
        &proxy::ProxyRequest {
            vault_profile: args.vault_profile.as_deref(),
            policy: args.policy.as_deref(),
            listen: args.listen.as_deref(),
            allow_external_interface: args.allow_external_interface,
            upstreams: &args.upstream,
        },
        &mut stdin.lock(),
    );

    let prepared = match outcome {
        proxy::ProxyOutcome::Ready(prepared) => *prepared,
        proxy::ProxyOutcome::Refused { reason } => {
            eprintln!("periskop: {reason}");
            return ExitCode::from(exit::ERROR);
        }
    };

    for note in &prepared.notes {
        eprintln!("periskop: {note}");
    }
    eprintln!("periskop: the vault opened in memory mode; nothing was written to disk.");

    // Printed from inside `serve`, after the bind, because `--listen 127.0.0.1:0`
    // is a real thing to ask for and the kernel picks the port. Announcing the
    // address that was *requested* would be a line that is sometimes false.
    match proxy::serve(prepared, |address| {
        eprintln!("periskop: listening on {address}");
    }) {
        Ok(()) => ExitCode::from(exit::PASS),
        Err(reason) => {
            eprintln!("periskop: {reason}");
            ExitCode::from(exit::ERROR)
        }
    }
}

fn report_hook_error(error: &HookError) -> ExitCode {
    eprintln!("error: {error}\n  → {}", error.suggestion());
    ExitCode::from(exit::ERROR)
}

fn run_serve_rpc(rules: Option<PathBuf>) -> ExitCode {
    let rules_root = rules.unwrap_or_else(default_rules_root);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    match rpc::serve(
        stdin.lock(),
        stdout.lock(),
        rules_root,
        env!("CARGO_PKG_VERSION"),
        now_rfc3339,
    ) {
        Ok(()) => ExitCode::from(exit::PASS),
        Err(e) => {
            eprintln!("periskop: rpc transport failed: {e}");
            ExitCode::from(exit::ERROR)
        }
    }
}

/// What one `scan` invocation was asked for.
///
/// Grouped rather than passed as five positional arguments, where two of the
/// three optional paths have the same type and swapping them at a call site
/// would compile.
struct ScanArgs {
    path: PathBuf,
    json: bool,
    rules: Option<PathBuf>,
    events: Option<PathBuf>,
    flows: Option<PathBuf>,
    policy: Option<PathBuf>,
    max_unparsed_ratio: Option<u64>,
}

/// Runs one observation pass and prints what it could and could not do.
///
/// Three exit codes and no fourth. Zero says the machine was watched, whatever
/// it turned out to be doing. `INSUFFICIENT_COVERAGE` says nothing was watched,
/// which is the honest reading of a sensor that could not start: the pass ran,
/// and it saw too little to stand behind any statement about this machine's
/// traffic. `ERROR` is reserved for the disk, because a directory that cannot be
/// written is the caller's problem rather than the sensor's answer.
fn run_sensor(args: &SensorArgs) -> ExitCode {
    let run = match sensor::run(&sensor::SensorRequest {
        out_dir: &args.out,
        host_id: args.host_id.as_deref(),
        codebase_processes: &args.scope_processes,
        benign_hosts: &args.benign_hosts,
    }) {
        Ok(run) => run,
        Err(e) => {
            eprintln!("periskop: {e}");
            return ExitCode::from(exit::ERROR);
        }
    };

    match serde_json::to_string_pretty(&run.status) {
        Ok(status) => println!("{status}"),
        Err(e) => {
            // The status is the whole product of this command. A pass whose
            // account of itself cannot be printed has told the caller nothing,
            // and exiting zero on that would be worse than the write failing.
            eprintln!("periskop: the sensor status could not be serialized: {e}");
            return ExitCode::from(exit::ERROR);
        }
    }
    eprintln!("periskop: wrote {}", run.record_file.display());

    if run.status.observed() {
        ExitCode::from(exit::PASS)
    } else {
        ExitCode::from(exit::INSUFFICIENT_COVERAGE)
    }
}

fn run_scan(args: ScanArgs) -> ExitCode {
    let ScanArgs {
        path,
        json,
        rules,
        events,
        flows,
        policy,
        max_unparsed_ratio,
    } = args;

    if !path.is_dir() {
        eprintln!("periskop: {} is not a directory", path.display());
        return ExitCode::from(exit::ERROR);
    }

    let rules_root = rules.unwrap_or_else(default_rules_root);
    if !rules_root.is_dir() {
        eprintln!(
            "periskop: no rule directory at {}. Pass --rules to point at one.",
            rules_root.display()
        );
        return ExitCode::from(exit::ERROR);
    }

    // A path that does not resolve stops the run rather than being read as an
    // empty stream. The difference matters more here than anywhere else in this
    // command: a mistyped directory would otherwise produce a report claiming
    // static_plus_runtime with nothing observed, which reads as a hooked
    // application that made no calls.
    let event_dir = match resolve_source_dir(events, EVENT_DIR_VAR) {
        Ok(dir) => dir,
        Err(given) => {
            eprintln!(
                "periskop: no event directory at {}. Run `periskop hook install` first, or drop --events for a static scan.",
                given.display()
            );
            return ExitCode::from(exit::ERROR);
        }
    };

    // The same rule, and the stakes are higher: a mistyped flow directory would
    // otherwise produce a report claiming `full` with no traffic in it, which
    // reads as a machine that sent nothing.
    let flow_dir = match resolve_source_dir(flows, FLOW_DIR_VAR) {
        Ok(dir) => dir,
        Err(given) => {
            eprintln!(
                "periskop: no flow directory at {}. Drop --flows for a scan without the network source.",
                given.display()
            );
            return ExitCode::from(exit::ERROR);
        }
    };

    // A policy named on the command line and not there stops the run, for the
    // reason the two directories above do: silently falling back to the engine's
    // defaults would hand back a report decided under rules nobody wrote, and the
    // one threshold that has no default would go on being undeclared while the
    // user believed they had declared it. A policy file that is simply absent
    // from the project is the ordinary case and stops nothing.
    let policy_path = match policy::resolve(policy, &path) {
        Ok(found) => found,
        Err(given) => {
            eprintln!(
                "periskop: no policy file at {}. Drop --policy to run on the engine's thresholds.",
                given.display()
            );
            return ExitCode::from(exit::ERROR);
        }
    };
    // A file that is there and cannot be used is not resolved here: it becomes a
    // POLICY_LOAD_ERROR diagnostic and a failing rule hit inside the report, so
    // the refusal survives in the artefact rather than only on this terminal.
    let scan_policy = policy_path
        .as_deref()
        .map_or_else(periskop_cli::policy::ScanPolicy::default, policy::load);

    // The clock is read before anything else runs. A report whose envelope
    // carries an invented timestamp is not auditable, and the previous behaviour
    // was to fall back to the epoch, which prints as a real date and reads as
    // one. Refusing to produce the report at all is the honest answer.
    let generated_at = match now_rfc3339() {
        Ok(now) => now,
        Err(e) => {
            eprintln!("periskop: {e}");
            return ExitCode::from(exit::ERROR);
        }
    };

    let outcome = scan::run_with_sources(
        scan::ScanRequest {
            project_root: &path,
            rules_root: &rules_root,
            tool_version: env!("CARGO_PKG_VERSION"),
            generated_at,
        },
        scan::ScanSources {
            event_dir: event_dir.as_deref(),
            flow_dir: flow_dir.as_deref(),
        },
        // The reconciliation thresholds come from the policy document, which is
        // where the contract puts them. They are deliberately not flags: a knob
        // that changes which findings exist and leaves no trace in the report is
        // worse than no knob, and the policy is carried into `policy_ref` where
        // an auditor can read which thresholds decided this run.
        scan_policy,
    );

    for error in &outcome.rule_errors {
        eprintln!("periskop: rule problem: {error}");
    }

    let output = if json {
        match periskop_report::to_canonical_json(&outcome.report) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("periskop: could not serialize the report: {e}");
                return ExitCode::from(exit::ERROR);
            }
        }
    } else {
        render::summary(&outcome.report)
    };
    print!("{output}");

    // Coverage is checked before the verdict. A scan that could not read enough
    // of the tree has not earned the right to report a pass, and giving that its
    // own exit code lets a pipeline tell "clean" apart from "did not look".
    if let Some(limit) = max_unparsed_ratio {
        let ratio = outcome.report.coverage.unparsed_ratio_basis_points();
        if ratio > limit {
            eprintln!(
                "periskop: unreadable share is {ratio} basis points, above the limit of {limit}"
            );
            return ExitCode::from(exit::INSUFFICIENT_COVERAGE);
        }
    }

    match outcome.report.verdict {
        periskop_report::Verdict::Fail => ExitCode::from(exit::FAIL),
        _ => ExitCode::from(exit::PASS),
    }
}

/// Environment variable naming the hook's event directory.
///
/// The same name `hook install` prints, so the two commands agree without the
/// user carrying a path between them.
const EVENT_DIR_VAR: &str = "PERISKOP_EVENT_DIR";

/// Environment variable naming the sensor's flow directory.
///
/// The sensor runs under a different privilege from the scan and usually writes
/// its records somewhere the scan is pointed at afterwards, so the path is
/// worth naming once in an environment rather than on every invocation.
const FLOW_DIR_VAR: &str = "PERISKOP_FLOW_DIR";

/// Decides whether this run has a given observation source, and refuses a path
/// that is not there.
///
/// `Ok(None)` is the run without it: no flag, no variable, and no directory is
/// looked for. An empty variable counts as unset, because an exported name with
/// no value is how a shell says nothing rather than how it says "here".
fn resolve_source_dir(flag: Option<PathBuf>, variable: &str) -> Result<Option<PathBuf>, PathBuf> {
    let requested = flag.or_else(|| {
        std::env::var_os(variable)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    });

    match requested {
        Some(dir) if dir.is_dir() => Ok(Some(dir)),
        Some(dir) => Err(dir),
        None => Ok(None),
    }
}

/// Where rules live when the caller does not say.
///
/// Looks next to the executable first, which is how an installed build finds the
/// rules shipped alongside it, then falls back to the repository layout so the
/// binary works from a development checkout without extra flags.
fn default_rules_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("rules");
            if beside.is_dir() {
                return beside;
            }
        }
    }
    PathBuf::from("rules")
}
