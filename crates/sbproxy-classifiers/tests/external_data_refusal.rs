// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The ONNX `external_data` seam: a model may not name a file outside its
//! own directory, and may not name one inside it either.
//!
//! GHSA-h668-6x6g-f8r5. An ONNX `TensorProto` can set `data_location:
//! EXTERNAL` and carry an `external_data` entry whose `location` value is a
//! path. `tract-onnx` up to 0.21.16 resolved that value with
//! `PathBuf::from(model_dir).join(location)` and no check of any kind, and
//! `Path::join` with an absolute argument discards the base, so
//! `location: "/etc/passwd"` read `/etc/passwd` and `location: "../../secret"`
//! walked out of the model directory. Operators point sbproxy at model files
//! they did not author, so the bytes of that field are attacker-controlled.
//! This workspace is held at 0.21, where that resolution is still
//! unsanitized, so refusing outright is what closes the advisory rather than
//! a belt beside an upstream brace. These tests therefore run against a
//! vulnerable runtime, which is the only configuration in which they prove
//! anything.
//!
//! Every loader in this crate parses the protobuf first and then translates
//! it with no model directory in the parsing context, which is the state the
//! ONNX spec reserves for "external data cannot be resolved". These tests
//! carry the malicious model that must be refused and the self-contained
//! model that must still load.

use std::path::{Path, PathBuf};

use prost_011::Message as _;
use sbproxy_classifiers::{LoadOptions, OnnxClassifier, OnnxEmbedder, OnnxTokenClassifier};
use tract_onnx::pb::{
    tensor_proto, GraphProto, ModelProto, OperatorSetIdProto, StringStringEntryProto, TensorProto,
    ValueInfoProto,
};

/// Exactly eight bytes, which is what a `[1, 2]` float tensor wants, so the
/// load fails because the reference was refused rather than because the
/// tensor came out the wrong shape. The content is a marker rather than
/// plausible float data so a leak is unambiguous: any message carrying
/// `CANARY` carried bytes out of a file the load had no business reading.
const DECOY_BYTES: &[u8; 8] = b"CANARY!!";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A one-initializer graph whose only tensor lives in an external file at
/// `location`.
fn model_with_external_tensor(location: &str) -> Vec<u8> {
    let model = ModelProto {
        ir_version: 8,
        producer_name: "sbproxy-external-data-test".to_string(),
        opset_import: vec![OperatorSetIdProto {
            domain: String::new(),
            version: 13,
        }],
        graph: Some(GraphProto {
            name: "external-data-graph".to_string(),
            initializer: vec![TensorProto {
                dims: vec![1, 2],
                data_type: tensor_proto::DataType::Float as i32,
                name: "logits".to_string(),
                data_location: Some(tensor_proto::DataLocation::External as i32),
                external_data: vec![StringStringEntryProto {
                    key: "location".to_string(),
                    value: location.to_string(),
                }],
                ..Default::default()
            }],
            output: vec![ValueInfoProto {
                name: "logits".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    model.encode(&mut bytes).expect("encode model proto");
    bytes
}

/// Stage `model.onnx` in its own directory with a decoy file the model tries
/// to read, and a tokenizer beside the model. Returns
/// `(tempdir, model_path, tokenizer_path, decoy_path)`.
fn stage(location_for: fn(&Path) -> String) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let model_dir = dir.path().join("model");
    let outside_dir = dir.path().join("outside");
    std::fs::create_dir_all(&model_dir).expect("create model dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");

    let decoy = outside_dir.join("secret.bin");
    std::fs::write(&decoy, DECOY_BYTES).expect("write decoy");

    let model_path = model_dir.join("model.onnx");
    std::fs::write(
        &model_path,
        model_with_external_tensor(&location_for(&decoy)),
    )
    .expect("write model");

    let tokenizer_path = model_dir.join("tokenizer.json");
    std::fs::copy(fixture("tiny_tokenizer.json"), &tokenizer_path).expect("copy tokenizer");

    (dir, model_path, tokenizer_path, decoy)
}

/// A refusal may not echo what it declined to read: not the host path the
/// model named, not that file's name, and not a byte of its contents. The
/// `location` value is a path the attacker chose in order to learn whether it
/// exists, so a refusal that repeats it answers the question it refused.
fn assert_discloses_nothing(message: &str, decoy: &Path) {
    let lower = message.to_ascii_lowercase();
    assert!(
        !lower.contains(&decoy.display().to_string().to_ascii_lowercase()),
        "refusal named the path it declined to read: {message}"
    );
    assert!(
        !message.contains("secret.bin"),
        "refusal named the file it declined to read: {message}"
    );
    assert!(
        !message.contains("CANARY"),
        "refusal leaked the contents of the file it declined to read: {message}"
    );
}

#[test]
fn classifier_refuses_a_model_whose_external_data_names_an_absolute_path() {
    let (_dir, model_path, tokenizer_path, decoy) = stage(|decoy| decoy.display().to_string());

    let error = match OnnxClassifier::load(&model_path, &tokenizer_path) {
        Ok(_) => panic!("a model naming a file outside its own directory must be refused"),
        Err(error) => error,
    };

    let message = format!("{error:#}");
    assert!(
        message.contains("external tensor data"),
        "refusal should name the external-data seam, got: {message}"
    );
    assert_discloses_nothing(&message, &decoy);
}

#[test]
fn classifier_refuses_a_model_whose_external_data_walks_out_of_its_directory() {
    let (_dir, model_path, tokenizer_path, decoy) = stage(|_| "../outside/secret.bin".to_string());

    let error = match OnnxClassifier::load(&model_path, &tokenizer_path) {
        Ok(_) => panic!("a model walking out of its own directory must be refused"),
        Err(error) => error,
    };

    assert_discloses_nothing(&format!("{error:#}"), &decoy);
}

#[test]
fn embedder_refuses_a_model_whose_external_data_names_an_absolute_path() {
    let (_dir, model_path, tokenizer_path, decoy) = stage(|decoy| decoy.display().to_string());

    let error = match OnnxEmbedder::load(&model_path, &tokenizer_path) {
        Ok(_) => panic!("a model naming a file outside its own directory must be refused"),
        Err(error) => error,
    };

    let message = format!("{error:#}");
    assert!(
        message.contains("external tensor data"),
        "refusal should name the external-data seam, got: {message}"
    );
    assert_discloses_nothing(&message, &decoy);
}

#[test]
fn token_classifier_refuses_a_model_whose_external_data_names_an_absolute_path() {
    let (_dir, model_path, tokenizer_path, decoy) = stage(|decoy| decoy.display().to_string());

    let error = match OnnxTokenClassifier::load(&model_path, &tokenizer_path, 128) {
        Ok(_) => panic!("a model naming a file outside its own directory must be refused"),
        Err(error) => error,
    };

    assert_discloses_nothing(&format!("{error:#}"), &decoy);
}

#[test]
fn a_self_contained_model_still_loads() {
    let classifier = OnnxClassifier::load(
        &fixture("tiny_classifier.onnx"),
        &fixture("tiny_tokenizer.json"),
    )
    .expect("the shipped self-contained fixture still loads");

    classifier
        .classify("hello")
        .expect("a loaded classifier still classifies");
}

/// The byte-snapshot loader, which is the guardrail embedding classifier's
/// path and the only one that takes bytes rather than a path.
///
/// tract alone would already refuse here, because the reader API has no model
/// directory to resolve against. That is exactly why this test exists: the
/// walk runs on this path too, so the refusal is ours and carries our wording
/// rather than depending on a runtime property that a future tract could
/// change. Without this the loader family would be the one seam with no test.
#[test]
fn the_byte_snapshot_embedder_refuses_external_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let decoy = dir.path().join("secret.bin");
    std::fs::write(&decoy, DECOY_BYTES).expect("write decoy");

    let model_bytes = model_with_external_tensor(&decoy.display().to_string());
    let tokenizer_bytes = std::fs::read(fixture("tiny_tokenizer.json")).expect("read tokenizer");

    let error = match OnnxEmbedder::load_from_bytes_with_options(
        &model_bytes,
        &tokenizer_bytes,
        &LoadOptions::default(),
    ) {
        Ok(_) => panic!("a byte snapshot declaring external data must be refused"),
        Err(error) => error,
    };

    let message = format!("{error:#}");
    assert!(
        message.contains("external tensor data"),
        "refusal should name the external-data seam, got: {message}"
    );
    assert_discloses_nothing(&message, &decoy);
}
