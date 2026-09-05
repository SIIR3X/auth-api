//! The control catalog of `docs/dev/security-model.md` names the tests that
//! pin each control. Renaming or deleting one of them fails here until the
//! catalog follows, so the model never cites a test that no longer exists.

use std::{collections::BTreeSet, fs, path::Path};

fn sources(dir: &Path, out: &mut String) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push_str(&fs::read_to_string(&path).unwrap());
        }
    }
}

#[test]
fn every_control_is_pinned_by_tests_that_exist() {
    let root = testkit::workspace_path("");
    let model = fs::read_to_string(root.join("docs/dev/security-model.md")).unwrap();

    let mut code = String::new();
    for dir in ["src", "tests", "crates/testkit/src"] {
        sources(&root.join(dir), &mut code);
    }

    let mut ids = BTreeSet::new();
    for row in model.lines().filter(|line| line.starts_with("| SEC-")) {
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        let (id, tests) = (cells[1], cells[3]);
        assert!(ids.insert(id.to_owned()), "{id} appears twice");

        let tests: Vec<&str> = tests
            .split(',')
            .map(|name| name.trim().trim_matches('`'))
            .filter(|name| !name.is_empty())
            .collect();
        assert!(!tests.is_empty(), "{id} names no test");
        for test in tests {
            assert!(
                code.contains(&format!("fn {test}(")),
                "{id} cites `{test}`, which no longer exists"
            );
        }
    }
    assert!(
        ids.len() >= 25,
        "the catalog lists only {} controls",
        ids.len()
    );
}
