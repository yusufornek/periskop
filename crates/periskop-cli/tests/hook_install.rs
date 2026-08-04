#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Installing a runtime hook.
//!
//! The tests build their own hook trees rather than reading the repository's.
//! `dist/` is not committed, so a fresh checkout has no built node hook and a
//! suite that read the real one would pass or fail depending on whether somebody
//! had run `npm run build` on that machine.
//!
//! What is covered here is the damage this command is capable of. It writes into
//! directories that belong to other software, so the cases that matter are the
//! ones where it must refuse: an installation already in place, a source that was
//! never built, a language it has no hook for, and the one python file that would
//! break an unrelated tool if it were ever copied.

use std::path::{Path, PathBuf};

use periskop_cli::hook::{self, Ambient, HookError, HookRequest, Language};

/// A throwaway directory tree, built by hand.
///
/// Written out rather than pulled in, matching the scan tests: a test only
/// dependency is still a dependency decision, and this needs a few lines.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        // The process id keeps two runs on one machine from deleting each
        // other's tree, which would surface as a failure with no obvious cause.
        let root =
            std::env::temp_dir().join(format!("periskop-hook-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A hooks directory shaped like the repository's, with both hooks present.
fn hooks_source(tree: &TempTree) -> PathBuf {
    tree.write("hooks/python/periskop_hook/__init__.py", "# package\n");
    tree.write("hooks/python/periskop_hook/writer.py", "# writer\n");
    tree.write(
        "hooks/python/periskop_hook/__pycache__/writer.pyc",
        "compiled",
    );
    tree.write("hooks/python/periskop-hook.pth", "import periskop_hook\n");
    // The fallback mechanism, and the file that must never reach site-packages.
    tree.write("hooks/python/sitecustomize.py", "# chained fallback\n");

    tree.write("hooks/node/dist/preload.js", "// preload\n");
    tree.write("hooks/node/dist/writer.js", "// writer\n");
    tree.write("hooks/node/dist/writer.test.js", "// test\n");
    tree.path("hooks")
}

fn request<'a>(
    language: Language,
    source_root: &'a Path,
    target: Option<&'a Path>,
    event_dir: &'a Path,
    force: bool,
) -> HookRequest<'a> {
    HookRequest {
        language,
        source_root,
        target,
        event_dir,
        force,
    }
}

fn value_of<'a>(vars: &'a [hook::EnvVar], name: &str) -> &'a str {
    vars.iter()
        .find(|var| var.name == name)
        .map(|var| var.value.as_str())
        .unwrap_or_else(|| panic!("no {name} in {vars:?}"))
}

#[test]
fn an_unknown_language_names_the_ones_that_exist() {
    // The failure this prevents is a typo answered with silence. A hook that was
    // never installed produces no events, and a run with no events looks exactly
    // like a run where nothing called a provider.
    let error = "ruby".parse::<Language>().unwrap_err();
    let HookError::UnknownLanguage { given } = &error else {
        panic!("expected an unknown language, got {error:?}");
    };
    assert_eq!(given, "ruby");
    assert!(error.to_string().contains("ruby"), "{error}");
    assert!(error.suggestion().contains("python"), "{error:?}");
    assert!(error.suggestion().contains("node"), "{error:?}");

    assert_eq!("python".parse::<Language>().unwrap(), Language::Python);
    assert_eq!("node".parse::<Language>().unwrap(), Language::Node);
}

#[test]
fn printing_the_environment_writes_nothing() {
    let tree = TempTree::new("print-env-python");
    let source = hooks_source(&tree);
    let events = tree.path("events");

    let vars = hook::env_vars(
        &request(Language::Python, &source, None, &events, false),
        &Ambient::default(),
    )
    .unwrap();

    // The import path is the directory holding the package, not the package.
    assert_eq!(
        value_of(&vars, "PYTHONPATH"),
        source.join("python").display().to_string()
    );
    assert_eq!(
        value_of(&vars, "PERISKOP_EVENT_DIR"),
        events.display().to_string()
    );

    // The event directory is the hook's, and printing where it will go is not
    // the same as creating it. A process that records nothing should leave
    // nothing behind.
    assert!(!events.exists(), "print-env created {}", events.display());
}

#[test]
fn an_existing_environment_variable_is_kept_in_front() {
    // A debugger, a coverage tool or a vendor agent is routinely already in
    // NODE_OPTIONS. Assigning over it would read as correct and remove it.
    let tree = TempTree::new("print-env-node");
    let source = hooks_source(&tree);
    let events = tree.path("events");

    let vars = hook::env_vars(
        &request(Language::Node, &source, None, &events, false),
        &Ambient {
            node_options: Some("--require /opt/tracer.js".to_owned()),
            python_path: None,
        },
    )
    .unwrap();

    let node_options = value_of(&vars, "NODE_OPTIONS");
    assert!(
        node_options.starts_with("--require /opt/tracer.js "),
        "the existing value was dropped: {node_options}"
    );
    assert!(
        node_options.ends_with(&format!(
            "--require {}",
            source.join("node/dist/preload.js").display()
        )),
        "{node_options}"
    );
}

#[test]
fn installing_places_the_payload_and_leaves_sitecustomize_behind() {
    let tree = TempTree::new("install-python");
    let source = hooks_source(&tree);
    let target = tree.path("site-packages");
    let events = tree.path("events");

    let installed = hook::install(&request(
        Language::Python,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap();

    assert!(!installed.replaced);
    assert!(target.join("periskop_hook/__init__.py").is_file());
    assert!(target.join("periskop_hook/writer.py").is_file());
    assert!(target.join("periskop-hook.pth").is_file());

    // Only one sitecustomize can win an import, and the loser fails silently.
    // Copying this one into site-packages is the single installation mistake
    // that breaks an unrelated tool with nothing to say why.
    assert!(
        !target.join("sitecustomize.py").exists(),
        "sitecustomize.py reached site-packages"
    );
    // Compiled caches belong to the interpreter that made them.
    assert!(!target.join("periskop_hook/__pycache__").exists());

    // The environment now points at the copy rather than at the checkout it
    // came from, which is what survives the checkout moving.
    let vars = hook::env_vars(
        &request(Language::Python, &source, Some(&target), &events, false),
        &Ambient::default(),
    )
    .unwrap();
    assert_eq!(
        value_of(&vars, "PYTHONPATH"),
        target.display().to_string(),
        "{vars:?}"
    );
}

#[test]
fn a_second_install_refuses_and_changes_nothing() {
    let tree = TempTree::new("install-twice");
    let source = hooks_source(&tree);
    let target = tree.path("site-packages");
    let events = tree.path("events");

    hook::install(&request(
        Language::Python,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap();
    // Somebody else's edit, or a version this command did not write.
    std::fs::write(target.join("periskop_hook/__init__.py"), "# local edit\n").unwrap();

    let error = hook::install(&request(
        Language::Python,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap_err();

    let HookError::AlreadyInstalled { occupied } = &error else {
        panic!("expected a refusal, got {error:?}");
    };
    assert!(
        occupied.contains(&target.join("periskop_hook")),
        "{error:?}"
    );
    assert!(error.suggestion().contains("--force"), "{error:?}");
    assert_eq!(
        std::fs::read_to_string(target.join("periskop_hook/__init__.py")).unwrap(),
        "# local edit\n",
        "the refused install still wrote over the existing one"
    );
}

#[test]
fn force_replaces_rather_than_merges() {
    let tree = TempTree::new("install-force");
    let source = hooks_source(&tree);
    let target = tree.path("site-packages");
    let events = tree.path("events");

    hook::install(&request(
        Language::Python,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap();
    // A module an older version shipped and this one does not. Merging would
    // leave it importable next to the new package.
    std::fs::write(target.join("periskop_hook/legacy.py"), "# removed\n").unwrap();

    let installed = hook::install(&request(
        Language::Python,
        &source,
        Some(&target),
        &events,
        true,
    ))
    .unwrap();

    assert!(installed.replaced);
    assert!(target.join("periskop_hook/__init__.py").is_file());
    assert!(
        !target.join("periskop_hook/legacy.py").exists(),
        "a file from the previous installation survived"
    );
}

#[test]
fn installing_the_node_hook_points_the_environment_at_the_copy() {
    let tree = TempTree::new("install-node");
    let source = hooks_source(&tree);
    let target = tree.path("vendor");
    let events = tree.path("events");

    hook::install(&request(
        Language::Node,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap();

    assert!(target.join("periskop-hook/preload.js").is_file());
    assert!(target.join("periskop-hook/writer.js").is_file());
    // The hook's own suite exercises the hook rather than running alongside it.
    assert!(!target.join("periskop-hook/writer.test.js").exists());

    let vars = hook::env_vars(
        &request(Language::Node, &source, Some(&target), &events, false),
        &Ambient::default(),
    )
    .unwrap();
    assert_eq!(
        value_of(&vars, "NODE_OPTIONS"),
        format!(
            "--require {}",
            target.join("periskop-hook/preload.js").display()
        )
    );
}

#[test]
fn a_node_hook_that_was_never_built_is_reported_rather_than_copied() {
    // The failure this catches: an install that reports success over an empty
    // dist. The application then starts with NODE_OPTIONS pointing at a file
    // that does not exist, node ignores it, and the run records nothing while
    // every message said the hook was installed.
    let tree = TempTree::new("node-unbuilt");
    tree.write("hooks/node/package.json", "{}\n");
    let source = tree.path("hooks");
    let events = tree.path("events");
    let target = tree.path("vendor");

    let error = hook::install(&request(
        Language::Node,
        &source,
        Some(&target),
        &events,
        false,
    ))
    .unwrap_err();

    let HookError::NotBuilt { language, probe } = &error else {
        panic!("expected an unbuilt source, got {error:?}");
    };
    assert_eq!(*language, Language::Node);
    assert!(probe.ends_with("preload.js"), "{probe:?}");
    assert!(error.suggestion().contains("npm run build"), "{error:?}");
    assert!(
        !target.exists(),
        "the destination was created for an install that could not happen"
    );
}

#[test]
fn installing_without_a_destination_says_how_to_name_one() {
    let tree = TempTree::new("no-target");
    let source = hooks_source(&tree);
    let events = tree.path("events");

    let error =
        hook::install(&request(Language::Python, &source, None, &events, false)).unwrap_err();

    let HookError::TargetRequired { language } = &error else {
        panic!("expected a missing destination, got {error:?}");
    };
    assert_eq!(*language, Language::Python);
    assert!(error.suggestion().contains("--target"), "{error:?}");
    assert!(error.suggestion().contains("--print-env"), "{error:?}");
}

#[test]
fn a_relative_event_directory_is_printed_as_an_absolute_one() {
    // The variable is read by a process started from a working directory this
    // command cannot know. A relative path would resolve somewhere else there,
    // and the events would land in a directory nobody looks in.
    let tree = TempTree::new("relative-event-dir");
    let source = hooks_source(&tree);
    let events = PathBuf::from(".periskop/events");

    let vars = hook::env_vars(
        &request(Language::Python, &source, None, &events, false),
        &Ambient::default(),
    )
    .unwrap();

    let printed = PathBuf::from(value_of(&vars, "PERISKOP_EVENT_DIR"));
    assert!(printed.is_absolute(), "{printed:?}");
    assert!(printed.ends_with(".periskop/events"), "{printed:?}");
}
