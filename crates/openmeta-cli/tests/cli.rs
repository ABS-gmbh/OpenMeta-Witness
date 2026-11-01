use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

fn openmeta(data: &Path) -> Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("openmeta");
    cmd.env("NO_COLOR", "1").arg("--data-dir").arg(data);
    cmd
}

fn publish(data: &Path, version: &str, timestamp: u64) {
    let digest = format!("{:064x}", timestamp);
    openmeta(data)
        .args(["publish", "--publisher", "publisher-a"])
        .args(["--purl", &format!("pkg:cargo/examplelib@{version}")])
        .args(["--repository", "https://git.example.org/examplelib.git"])
        .args(["--source-revision", &format!("v{version}")])
        .args(["--digest", &digest, "--license", "Apache-2.0"])
        .args(["--dependency", "pkg:cargo/serde@1.0.210=^1.0"])
        .args(["--vulnerability", "CVE-2026-0001=not_affected"])
        .args(["--timestamp", &timestamp.to_string()])
        .assert()
        .success()
        .stdout(contains("[VERIFIED]"));
}

fn checkpoint(data: &Path, timestamp: u64) {
    openmeta(data)
        .args([
            "checkpoint",
            "create",
            "--timestamp",
            &timestamp.to_string(),
        ])
        .assert()
        .success();
}

fn observe(data: &Path, witness: &str) -> assert_cmd::assert::Assert {
    openmeta(data)
        .args(["witness", "observe", witness])
        .assert()
}

fn setup(data: &Path) {
    openmeta(data)
        .args(["identity", "new", "publisher-a"])
        .assert()
        .success();
    openmeta(data)
        .args(["log", "init", "--operator", "publisher-a"])
        .assert()
        .success();
    for witness in ["witness-a", "witness-b"] {
        openmeta(data)
            .args(["witness", "new", witness])
            .assert()
            .success();
    }
    publish(data, "1.0.0", 1_767_225_600);
    checkpoint(data, 1_767_225_700);
    for witness in ["witness-a", "witness-b"] {
        observe(data, witness)
            .success()
            .stdout(contains("accepted checkpoint size 1"));
    }
}

#[test]
fn identity_output_never_reveals_the_secret_key() {
    let dir = tempfile::tempdir().unwrap();
    let output = openmeta(dir.path())
        .args(["identity", "new", "publisher-a"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let secret = fs::read_to_string(dir.path().join("keys/publisher-a.secret")).unwrap();
    let public = fs::read_to_string(dir.path().join("keys/publisher-a.pub")).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(public.trim()));
    assert!(!stdout.contains(secret.trim()));
    openmeta(dir.path())
        .args(["identity", "new", "publisher-a"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn state_persists_across_process_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    setup(data);

    publish(data, "1.1.0", 1_767_225_800);
    checkpoint(data, 1_767_225_900);
    for witness in ["witness-a", "witness-b"] {
        observe(data, witness)
            .success()
            .stdout(contains("accepted checkpoint size 2"));
        observe(data, witness)
            .success()
            .stdout(contains("already observed"));
    }

    openmeta(data)
        .args(["witness", "compare", "witness-a", "witness-b"])
        .assert()
        .success()
        .stdout(contains("agree on size 1").and(contains("agree on size 2")));
    openmeta(data)
        .args(["witness", "show", "witness-a"])
        .assert()
        .success()
        .stdout(contains("observed size    1").and(contains("observed size    2")));
    openmeta(data)
        .args(["checkpoint", "list"])
        .assert()
        .success()
        .stdout(contains("size    1").and(contains("size    2")));
    openmeta(data)
        .args(["inspect", "--purl", "pkg:cargo/examplelib@1.1.0"])
        .assert()
        .success()
        .stdout(contains("record #1").and(contains("CVE-2026-0001")));
    openmeta(data)
        .args(["log", "verify"])
        .assert()
        .success()
        .stdout(contains("2 records replayed"));
    openmeta(data)
        .args(["verify", "record", "1", "--publisher", "publisher-a"])
        .assert()
        .success()
        .stdout(contains("included at index 1 of checkpoint size 2"));
}

#[test]
fn exported_proof_bundles_verify_and_tampering_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    setup(data);
    let bundle = data.join("proof.json");
    openmeta(data)
        .args(["prove", "0", "--out"])
        .arg(&bundle)
        .assert()
        .success();
    openmeta(data)
        .args(["verify", "proof"])
        .arg(&bundle)
        .assert()
        .success()
        .stdout(contains("[VERIFIED]"));

    let original = fs::read_to_string(&bundle).unwrap();
    let tampered = data.join("tampered.json");
    fs::write(&tampered, original.replace("Apache-2.0", "MIT")).unwrap();
    openmeta(data)
        .args(["verify", "proof"])
        .arg(&tampered)
        .assert()
        .code(2)
        .stdout(contains("[DETECTED]").and(contains("signature verification failed")));

    let wrong_key = "11".repeat(32);
    openmeta(data)
        .args(["verify", "proof"])
        .arg(&bundle)
        .args(["--publisher-key", &wrong_key])
        .assert()
        .failure();

    openmeta(data)
        .args(["simulate", "tamper", "0"])
        .assert()
        .success()
        .stdout(contains("[DETECTED]").and(contains("[MISSED]").not()));
}

#[test]
fn conflicting_checkpoints_are_detected_by_witness_comparison() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    setup(data);
    publish(data, "1.1.0", 1_767_225_800);
    checkpoint(data, 1_767_225_900);
    observe(data, "witness-a").success();

    openmeta(data)
        .args([
            "simulate",
            "equivocate",
            "--witness",
            "witness-b",
            "--publisher",
            "publisher-a",
        ])
        .assert()
        .success()
        .stdout(contains("witness-b accepted checkpoint size 2"));

    openmeta(data)
        .args(["witness", "compare", "witness-a", "witness-b"])
        .assert()
        .code(2)
        .stdout(contains("agree on size 1").and(contains("signed two different roots for size 2")));
    openmeta(data)
        .args(["witness", "show", "witness-b"])
        .assert()
        .success()
        .stdout(contains("[DETECTED]"));

    openmeta(data)
        .args([
            "simulate",
            "equivocate",
            "--witness",
            "witness-a",
            "--publisher",
            "publisher-a",
        ])
        .assert()
        .code(2)
        .stdout(contains("signed two different roots for size 2"));

    openmeta(data)
        .args(["checkpoint", "show", "--json"])
        .assert()
        .success()
        .stdout(contains("\"signature\""));
}

#[test]
fn checkpoints_are_anchored_and_verified() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    setup(data);
    openmeta(data)
        .args(["anchor", "verify"])
        .assert()
        .success()
        .stdout(contains("not anchored"));
    openmeta(data)
        .args(["anchor", "submit"])
        .assert()
        .success()
        .stdout(contains("anchored at height 0"));
    openmeta(data)
        .args(["anchor", "verify"])
        .assert()
        .success()
        .stdout(contains("matches the commitment anchored at height 0"));
    openmeta(data)
        .args(["anchor", "list"])
        .assert()
        .success()
        .stdout(contains("size    1"));
}

#[test]
fn checkpoint_files_can_be_compared() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    setup(data);
    let first = data.join("cp1.json");
    let output = openmeta(data)
        .args(["checkpoint", "show", "--json"])
        .output()
        .unwrap();
    fs::write(&first, &output.stdout).unwrap();
    publish(data, "1.1.0", 1_767_225_800);
    checkpoint(data, 1_767_225_900);
    let second = data.join("cp2.json");
    let output = openmeta(data)
        .args(["checkpoint", "show", "--json"])
        .output()
        .unwrap();
    fs::write(&second, &output.stdout).unwrap();

    openmeta(data)
        .args(["checkpoint", "compare"])
        .arg(&first)
        .arg(&second)
        .assert()
        .success()
        .stdout(contains("size 1 is a prefix of size 2"));

    let forged = data.join("forged.json");
    let text = fs::read_to_string(&second).unwrap();
    let root = serde_json::from_str::<serde_json::Value>(&text).unwrap()["checkpoint"]["root"]
        .as_str()
        .unwrap()
        .to_string();
    fs::write(&forged, text.replace(&root, &"ab".repeat(32))).unwrap();
    openmeta(data)
        .args(["checkpoint", "compare"])
        .arg(&first)
        .arg(&forged)
        .assert()
        .code(2)
        .stdout(contains("checkpoint signature is invalid"));
}

#[test]
fn demo_runs_end_to_end_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let demo_dir = dir.path().join("demo");
    let run = || {
        let output = assert_cmd::cargo_bin_cmd!("openmeta")
            .env("NO_COLOR", "1")
            .arg("demo")
            .arg("--dir")
            .arg(&demo_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let first = run();
    let second = run();
    assert_eq!(first, second);
    assert!(first.contains("witness-a: checkpoint size 1 signature valid"));
    assert!(first.contains("witness-b: checkpoint size 1 signature valid"));
    assert!(first.contains("license changed after signing"));
    assert!(first.contains("signed two different roots for size 3"));
    assert!(!first.contains("[MISSED]"));

    openmeta(&demo_dir)
        .args(["witness", "show", "witness-b"])
        .assert()
        .success()
        .stdout(contains("observed size    3").and(contains("[DETECTED]")));
}

#[test]
fn demo_refuses_to_clear_foreign_directories() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("important.txt"), "keep me").unwrap();
    assert_cmd::cargo_bin_cmd!("openmeta")
        .arg("demo")
        .arg("--dir")
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("was not created by the demo"));
    assert!(dir.path().join("important.txt").exists());
}
