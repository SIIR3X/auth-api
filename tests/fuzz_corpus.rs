//! The fuzz targets on stable: every curated seed and every recorded crash
//! (`fuzz/seeds/<target>/`, `fuzz/regressions/<target>/`) replayed, then random
//! inputs from proptest. Deep fuzzing runs on nightly with `make fuzz`; this
//! keeps what it found from coming back.
//!
//! Needs the `fuzzing` feature: `cargo nextest run --test fuzz_corpus --features fuzzing`.

use std::{fs, path::Path};

use auth_api::fuzzing::TARGETS;
use proptest::prelude::*;

fn replay(dir: &Path, target: &str, run: fn(&[u8])) -> usize {
    let Ok(entries) = fs::read_dir(dir.join(target)) else {
        return 0;
    };
    let mut replayed = 0;
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();
            // A panic names the input it came from.
            let outcome = std::panic::catch_unwind(|| run(&data));
            assert!(outcome.is_ok(), "{target}: {} fails", path.display());
            replayed += 1;
        }
    }
    replayed
}

#[test]
fn seeds_and_regressions_hold() {
    let fuzz = testkit::workspace_path("fuzz");
    for (target, run) in TARGETS {
        let seeds = replay(&fuzz.join("seeds"), target, *run);
        assert!(seeds > 0, "{target} has no seed in fuzz/seeds/{target}/");
        replay(&fuzz.join("regressions"), target, *run);
    }
}

#[test]
fn every_fuzz_target_is_declared() {
    let manifest = fs::read_to_string(testkit::workspace_path("fuzz/Cargo.toml")).unwrap();
    for (target, _) in TARGETS {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "{target} is missing from fuzz/Cargo.toml"
        );
        assert!(
            testkit::workspace_path(&format!("fuzz/fuzz_targets/{target}.rs")).is_file(),
            "fuzz/fuzz_targets/{target}.rs is missing"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_inputs_hold(target in 0..TARGETS.len(), data in proptest::collection::vec(any::<u8>(), 0..512)) {
        (TARGETS[target].1)(&data);
    }

    #[test]
    fn random_text_holds(target in 0..TARGETS.len(), text in "\\PC{0,256}") {
        (TARGETS[target].1)(text.as_bytes());
    }
}
