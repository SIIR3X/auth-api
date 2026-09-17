//! Static guards: patterns that must never reach the service code.
//!
//! Source scans that catch a whole class of mistake before any request is
//! sent. They read production code only: everything above the first
//! `#[cfg(test)]` of a file (test modules close the files here), minus
//! `tests.rs` files.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `(path relative to the package, production code)` of every source file.
fn production_sources() -> Vec<(String, String)> {
    let root = testkit::workspace_path("");
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name != "tests.rs"))
        .map(|path| {
            let content = fs::read_to_string(&path).unwrap();
            let production = match content.find("#[cfg(test)]") {
                Some(at) => content[..at].to_owned(),
                None => content,
            };
            let relative = path.strip_prefix(&root).unwrap().display().to_string();
            (relative, production)
        })
        .collect()
}

/// Lines of production code containing `needle`, as `file:line: text`.
fn occurrences(filter: impl Fn(&str) -> bool, needle: impl Fn(&str) -> bool) -> Vec<String> {
    production_sources()
        .into_iter()
        .filter(|(path, _)| filter(path))
        .flat_map(|(path, code)| {
            code.lines()
                .enumerate()
                .filter(|(_, line)| !line.trim_start().starts_with("//") && needle(line))
                .map(|(n, line)| format!("{path}:{}: {}", n + 1, line.trim()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn sql_is_never_assembled_from_strings() {
    // Values reach SQL as bind parameters only. The benchmark binaries
    // (`src/bin/`) create and drop their own databases by name and are not
    // part of the service.
    const CALLS: [&str; 5] = [
        "query(",
        "query_as(",
        "query_scalar(",
        "raw_sql(",
        "query_with(",
    ];
    let found = occurrences(
        |path| !path.starts_with("src/bin/"),
        |line| {
            CALLS.iter().any(|call| {
                line.split(call).skip(1).any(|args| {
                    let args = args.trim_start().trim_start_matches('&');
                    args.starts_with("format!") || args.starts_with("concat!")
                })
            })
        },
    );
    assert_eq!(found, Vec::<String>::new(), "SQL built from strings");
}

#[test]
fn there_is_no_unsafe_code() {
    let found = occurrences(
        |_| true,
        |line| {
            line.contains("unsafe {") || line.contains("unsafe fn") || line.contains("unsafe impl")
        },
    );
    assert_eq!(found, Vec::<String>::new());
}

#[test]
fn tls_verification_is_never_disabled() {
    let found = occurrences(|_| true, |line| line.contains("danger_accept_invalid"));
    assert_eq!(found, Vec::<String>::new());
}

#[test]
fn the_service_writes_nothing_to_stdout_or_stderr() {
    // Logs go through tracing, which the deployment filters and ships; stray
    // prints bypass both. The binary's own entry points may print.
    let found = occurrences(
        |path| path != "src/main.rs" && !path.starts_with("src/bin/"),
        |line| line.contains("println!") || line.contains("eprintln!") || line.contains("dbg!("),
    );
    assert_eq!(found, Vec::<String>::new());
}

#[test]
fn request_paths_never_unwrap() {
    // A panic in a handler drops the connection and hides the cause; request
    // paths return `AppError` instead.
    let found = occurrences(
        |path| {
            [
                "src/handlers/",
                "src/services/",
                "src/middleware/",
                "src/repositories/",
            ]
            .iter()
            .any(|dir| path.starts_with(dir))
        },
        |line| line.contains(".unwrap()"),
    );
    assert_eq!(found, Vec::<String>::new());
}

/// `migrations/SHA256SUMS` pins every migration already released.
#[test]
fn released_migrations_are_never_edited() {
    let root = testkit::workspace_path("");
    let pinned: BTreeMap<String, String> = fs::read_to_string(root.join("migrations/SHA256SUMS"))
        .expect("migrations/SHA256SUMS")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (digest, name) = line.split_once("  ").expect("`<sha256>  <file>` lines");
            (name.to_owned(), digest.to_owned())
        })
        .collect();

    let mut actual = BTreeMap::new();
    for entry in fs::read_dir(root.join("migrations")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "sql") {
            let digest: String = Sha256::digest(fs::read(&path).unwrap())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            actual.insert(
                path.file_name().unwrap().to_string_lossy().into_owned(),
                digest,
            );
        }
    }

    for (name, digest) in &pinned {
        match actual.get(name) {
            None => panic!("{name} was deleted: a released migration is never removed"),
            Some(current) => assert_eq!(
                current, digest,
                "{name} was edited after release: write a new migration instead"
            ),
        }
    }
    let unpinned: Vec<_> = actual
        .keys()
        .filter(|name| !pinned.contains_key(*name))
        .collect();
    assert!(
        unpinned.is_empty(),
        "new migrations {unpinned:?}: append them to migrations/SHA256SUMS \
         (`sha256sum migrations/NNNN_name.sql | sed 's|migrations/||' >> migrations/SHA256SUMS`)"
    );
}

/// The project is written in English. The French email templates are product
/// content and the fuzz inputs are raw bytes: both are exempt. Non-ASCII test
/// inputs are written as escapes (`"\u{e9}"`), which keeps them out of this scan.
#[test]
fn the_repository_is_written_in_english() {
    const EXEMPT: [&str; 4] = [
        "templates/emails/fr/",
        "fuzz/seeds/",
        "fuzz/regressions/",
        "Cargo.lock",
    ];
    // Latin letters with the diacritics French uses.
    // Escaped, so this guard does not flag itself.
    const FRENCH: &str = "\u{c0}\u{c2}\u{c6}\u{c7}\u{c8}\u{c9}\u{ca}\u{cb}\u{ce}\u{cf}\u{d4}\u{152}\u{d9}\u{db}\u{dc}\u{178}\u{e0}\u{e2}\u{e6}\u{e7}\u{e8}\u{e9}\u{ea}\u{eb}\u{ee}\u{ef}\u{f4}\u{153}\u{f9}\u{fb}\u{fc}\u{ff}";

    let root = testkit::workspace_path("");
    let listing = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files", "-z"])
        .output()
        .expect("git lists the tracked files");
    assert!(listing.status.success(), "git ls-files failed");

    let mut found = Vec::new();
    for path in listing.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = String::from_utf8_lossy(path);
        if EXEMPT.iter().any(|exempt| path.starts_with(exempt)) {
            continue;
        }
        let Ok(content) = fs::read_to_string(root.join(path.as_ref())) else {
            continue; // binary
        };
        for (n, line) in content.lines().enumerate() {
            if line.chars().any(|c| FRENCH.contains(c)) {
                found.push(format!("{path}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert_eq!(
        found,
        Vec::<String>::new(),
        "French text outside the exempt paths"
    );
}

#[test]
fn documented_schemas_have_unique_names() {
    // The OpenAPI document names a schema after its type: a second type with
    // the same name silently replaces the first, and the contract then checks
    // responses against the wrong shape.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for (path, code) in production_sources() {
        let mut documented = false;
        for line in code.lines() {
            let line = line.trim();
            if line.starts_with("#[derive(") && line.contains("ToSchema") {
                documented = true;
                continue;
            }
            if !documented || line.starts_with("#[") || line.starts_with("///") {
                continue;
            }
            documented = false;
            let Some(rest) = line
                .strip_prefix("pub struct ")
                .or_else(|| line.strip_prefix("pub enum "))
                .or_else(|| line.strip_prefix("struct "))
                .or_else(|| line.strip_prefix("enum "))
            else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if let Some(first) = seen.insert(name.clone(), path.clone()) {
                duplicates.push(format!("{name}: {first} and {path}"));
            }
        }
    }
    assert!(seen.len() > 50, "found only {} schemas", seen.len());
    assert_eq!(duplicates, Vec::<String>::new(), "schema names used twice");
}
