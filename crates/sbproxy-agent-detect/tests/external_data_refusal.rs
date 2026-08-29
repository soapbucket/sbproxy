// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The ONNX `external_data` seam for the JA4 CatBoost scorer.
//!
//! GHSA-h668-6x6g-f8r5. `tract-onnx` up to 0.21.16 resolved an
//! `external_data` `location` value with
//! `PathBuf::from(model_dir).join(location)` and no check of any kind, and
//! `Path::join` with an absolute argument discards the base. The scorer's
//! model file is operator-supplied through
//! `proxy.extensions.agent_detect.onnx_model_path`, so those bytes are not
//! ours. [`OnnxCatBoostScorer::load`] translates the parsed protobuf with no
//! model directory in the parsing context, which is the state ONNX reserves
//! for "external data cannot be resolved".

use std::path::{Path, PathBuf};

use prost_011::Message as _;
use sbproxy_agent_detect::OnnxCatBoostScorer;
use tract_onnx::pb::{
    tensor_proto, GraphProto, ModelProto, OperatorSetIdProto, StringStringEntryProto, TensorProto,
    ValueInfoProto,
};

/// Exactly eight bytes, which is what a `[1, 2]` float tensor wants, so the
/// load fails because the reference was refused rather than because the
/// tensor came out the wrong shape. A marker rather than plausible float
/// data, so a leak is unambiguous.
const DECOY_BYTES: &[u8; 8] = b"CANARY!!";

const FIXTURE_MODEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/ja4_catboost_fixture.onnx"
);

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
                name: "probability_tensor".to_string(),
                data_location: Some(tensor_proto::DataLocation::External as i32),
                external_data: vec![StringStringEntryProto {
                    key: "location".to_string(),
                    value: location.to_string(),
                }],
                ..Default::default()
            }],
            output: vec![ValueInfoProto {
                name: "probability_tensor".to_string(),
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

fn stage(location_for: fn(&Path) -> String) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let model_dir = dir.path().join("model");
    let outside_dir = dir.path().join("outside");
    std::fs::create_dir_all(&model_dir).expect("create model dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");

    let decoy = outside_dir.join("secret.bin");
    std::fs::write(&decoy, DECOY_BYTES).expect("write decoy");

    let model_path = model_dir.join("agents.onnx");
    std::fs::write(
        &model_path,
        model_with_external_tensor(&location_for(&decoy)),
    )
    .expect("write model");

    (dir, model_path, decoy)
}

/// A refusal may not echo what it declined to read: not the host path the
/// model named, not that file's name, and not a byte of its contents.
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
fn scorer_refuses_a_model_whose_external_data_names_an_absolute_path() {
    let (_dir, model_path, decoy) = stage(|decoy| decoy.display().to_string());

    let error = match OnnxCatBoostScorer::load(&model_path) {
        Ok(_) => panic!("a model naming a file outside its own directory must be refused"),
        Err(error) => error,
    };

    let message = format!("{error:#}");
    assert!(
        message.contains("external data"),
        "refusal should name the external-data seam, got: {message}"
    );
    assert_discloses_nothing(&message, &decoy);
}

#[test]
fn scorer_refuses_a_model_whose_external_data_walks_out_of_its_directory() {
    let (_dir, model_path, decoy) = stage(|_| "../outside/secret.bin".to_string());

    let error = match OnnxCatBoostScorer::load(&model_path) {
        Ok(_) => panic!("a model walking out of its own directory must be refused"),
        Err(error) => error,
    };

    assert_discloses_nothing(&format!("{error:#}"), &decoy);
}

#[test]
fn the_self_contained_vendored_model_still_loads() {
    OnnxCatBoostScorer::load(FIXTURE_MODEL).expect("the vendored fixture model still loads");
}
