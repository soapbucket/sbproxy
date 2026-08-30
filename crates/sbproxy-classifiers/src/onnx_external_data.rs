// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Refuse ONNX models that keep their tensors in a separate file.
//!
//! # The vector
//!
//! An ONNX `TensorProto` may set `data_location: EXTERNAL` and name a file in
//! its `external_data` `location` entry instead of carrying the tensor inline.
//! The runtime is then expected to open that file and use its bytes as the
//! tensor. `tract-onnx` up to and including 0.21.16 resolved the value as
//! `PathBuf::from(model_dir).join(location)` with no containment check, and
//! `Path::join` with an absolute argument discards the base. A model carrying
//! `location: "/etc/ssl/private/server.key"` read that file, and one carrying
//! `location: "../../../../etc/shadow"` walked out of the model directory. The
//! bytes then became a tensor the graph could route to an output. That is
//! GHSA-h668-6x6g-f8r5, and it is a read of any file the proxy user can open.
//!
//! Operators point sbproxy at ONNX files they did not author, so the bytes of
//! that field are attacker-controlled.
//!
//! # Why refuse rather than confine
//!
//! `tract-onnx` confines the value to the model directory from 0.21.17
//! onward, but this workspace resolves 0.21.10 and cannot move: 0.21.17 is
//! blocked by an exact `libm` pin one layer down, and 0.22 and 0.23 regress
//! the Gather op to a panic on out-of-range indices. See `deny.toml` and
//! `docs/model-pinning.md`. So this is not a second layer behind an upstream
//! fix, it is the layer that closes the advisory here. Three reasons it is
//! written this way:
//!
//! - A confined reference is still an **unbounded read**. Size budgets measure
//!   the `.onnx` file, so a 900-byte model naming a 40 GB sibling passes every
//!   one of them. Refusal is the only posture under which the file that was
//!   sized is the file that gets parsed.
//! - Nothing real uses it. Neither vendored fixture nor `all-MiniLM-L6-v2` at
//!   the pinned revision carries an external reference, and the only
//!   legitimate reason to split a model is the 2 GB protobuf ceiling, which
//!   the default 200 MB artifact budget refuses already.
//! - The property should not depend on which `tract` is underneath. This
//!   advisory has already moved that resolution once.
//!
//! # Disclosure discipline
//!
//! The refusal names the tensor and never the path it declined to read. The
//! `location` value is a host path the attacker chose in order to learn
//! whether it exists, so echoing it into a log, an error, or a metric label
//! would turn the refusal into the disclosure it exists to prevent. Note that
//! tract's own confinement error, from 0.21.17 onward, does echo the location
//! back, which is a further reason to refuse before the runtime ever sees the
//! proto. That refusal is also stricter than tract's: tract checks path
//! components, so it admits a symlink inside the model directory that points
//! out of it, while refusing the reference outright never resolves anything.

use anyhow::{anyhow, Result};
use tract_onnx::pb::{
    tensor_proto, AttributeProto, GraphProto, ModelProto, NodeProto, SparseTensorProto, TensorProto,
};

/// Refuse a model that keeps any of its tensors in a separate file.
///
/// Walks every `TensorProto` a [`ModelProto`] can reach: graph initializers,
/// sparse initializers, node attributes, subgraphs (recursively, which is
/// where `If` and `Loop` bodies live), function bodies, and both training
/// graphs. Call it on the parsed protobuf before handing it to tract.
///
/// # Errors
///
/// Returns an error naming the offending tensor, and nothing else, if any
/// reachable tensor declares external data.
pub fn reject_external_tensor_data(model: &ModelProto) -> Result<()> {
    if let Some(graph) = model.graph.as_ref() {
        reject_in_graph(graph)?;
    }
    for training in &model.training_info {
        if let Some(graph) = training.initialization.as_ref() {
            reject_in_graph(graph)?;
        }
        if let Some(graph) = training.algorithm.as_ref() {
            reject_in_graph(graph)?;
        }
    }
    for function in &model.functions {
        reject_in_nodes(&function.node)?;
    }
    Ok(())
}

fn reject_in_graph(graph: &GraphProto) -> Result<()> {
    for tensor in &graph.initializer {
        reject_in_tensor(tensor)?;
    }
    for tensor in &graph.sparse_initializer {
        reject_in_sparse_tensor(tensor)?;
    }
    reject_in_nodes(&graph.node)
}

fn reject_in_nodes(nodes: &[NodeProto]) -> Result<()> {
    for node in nodes {
        for attribute in &node.attribute {
            reject_in_attribute(attribute)?;
        }
    }
    Ok(())
}

fn reject_in_attribute(attribute: &AttributeProto) -> Result<()> {
    if let Some(tensor) = attribute.t.as_ref() {
        reject_in_tensor(tensor)?;
    }
    for tensor in &attribute.tensors {
        reject_in_tensor(tensor)?;
    }
    if let Some(tensor) = attribute.sparse_tensor.as_ref() {
        reject_in_sparse_tensor(tensor)?;
    }
    for tensor in &attribute.sparse_tensors {
        reject_in_sparse_tensor(tensor)?;
    }
    if let Some(graph) = attribute.g.as_ref() {
        reject_in_graph(graph)?;
    }
    for graph in &attribute.graphs {
        reject_in_graph(graph)?;
    }
    Ok(())
}

fn reject_in_sparse_tensor(tensor: &SparseTensorProto) -> Result<()> {
    if let Some(values) = tensor.values.as_ref() {
        reject_in_tensor(values)?;
    }
    if let Some(indices) = tensor.indices.as_ref() {
        reject_in_tensor(indices)?;
    }
    Ok(())
}

/// `data_location` and `external_data` are independent fields, and tract takes
/// the external branch off the first alone. Refusing on either keeps this
/// detector wider than the runtime it guards.
fn reject_in_tensor(tensor: &TensorProto) -> Result<()> {
    let external_location =
        tensor.data_location == Some(tensor_proto::DataLocation::External as i32);
    if external_location || !tensor.external_data.is_empty() {
        let name = if tensor.name.is_empty() {
            "<unnamed>"
        } else {
            &tensor.name
        };
        // Names the tensor, never the `location` value it declared.
        return Err(anyhow!(
            "ONNX external tensor data is unsupported for tensor {name:?}; \
             a model this process loads must hold its own tensors"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tract_onnx::pb::{
        AttributeProto, FunctionProto, NodeProto, StringStringEntryProto, TrainingInfoProto,
    };

    /// A tensor whose bytes live in another file. `location` is the field the
    /// advisory turns into a read.
    fn external_tensor(name: &str) -> TensorProto {
        TensorProto {
            name: name.to_string(),
            dims: vec![1],
            data_type: tensor_proto::DataType::Float as i32,
            data_location: Some(tensor_proto::DataLocation::External as i32),
            external_data: vec![StringStringEntryProto {
                key: "location".to_string(),
                value: "../../../../etc/shadow".to_string(),
            }],
            ..Default::default()
        }
    }

    fn graph_with_initializer(tensor: TensorProto) -> GraphProto {
        GraphProto {
            initializer: vec![tensor],
            ..Default::default()
        }
    }

    fn node_with_attribute(attribute: AttributeProto) -> NodeProto {
        NodeProto {
            attribute: vec![attribute],
            ..Default::default()
        }
    }

    fn assert_refused(model: &ModelProto, expected_tensor: &str) {
        let error = reject_external_tensor_data(model)
            .expect_err("a model declaring external tensor data must be refused");
        let message = error.to_string();
        assert!(
            message.contains("external tensor data"),
            "refusal should name the seam, got: {message}"
        );
        assert!(
            message.contains(expected_tensor),
            "refusal should name the tensor, got: {message}"
        );
        assert!(
            !message.contains("etc/shadow"),
            "refusal leaked the path it declined to read: {message}"
        );
    }

    #[test]
    fn a_self_contained_model_is_accepted() {
        let model = ModelProto {
            graph: Some(graph_with_initializer(TensorProto {
                name: "weight".to_string(),
                dims: vec![1],
                data_type: tensor_proto::DataType::Float as i32,
                float_data: vec![0.0],
                ..Default::default()
            })),
            ..Default::default()
        };
        reject_external_tensor_data(&model).expect("a self-contained model loads");
    }

    #[test]
    fn a_graph_initializer_is_refused() {
        let model = ModelProto {
            graph: Some(graph_with_initializer(external_tensor("initializer"))),
            ..Default::default()
        };
        assert_refused(&model, "initializer");
    }

    #[test]
    fn a_sparse_initializer_is_refused() {
        let model = ModelProto {
            graph: Some(GraphProto {
                sparse_initializer: vec![SparseTensorProto {
                    values: Some(external_tensor("sparse-values")),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "sparse-values");
    }

    #[test]
    fn a_sparse_index_tensor_is_refused() {
        let model = ModelProto {
            graph: Some(GraphProto {
                sparse_initializer: vec![SparseTensorProto {
                    indices: Some(external_tensor("sparse-indices")),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "sparse-indices");
    }

    #[test]
    fn a_node_attribute_tensor_is_refused() {
        let model = ModelProto {
            graph: Some(GraphProto {
                node: vec![node_with_attribute(AttributeProto {
                    t: Some(external_tensor("attribute-tensor")),
                    ..Default::default()
                })],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "attribute-tensor");
    }

    #[test]
    fn a_node_attribute_tensor_list_is_refused() {
        let model = ModelProto {
            graph: Some(GraphProto {
                node: vec![node_with_attribute(AttributeProto {
                    tensors: vec![external_tensor("attribute-tensors")],
                    ..Default::default()
                })],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "attribute-tensors");
    }

    /// `If` and `Loop` bodies live in a subgraph attribute. A walk that stops
    /// at the top-level graph misses every tensor in them.
    #[test]
    fn a_subgraph_tensor_is_refused() {
        let model = ModelProto {
            graph: Some(GraphProto {
                node: vec![node_with_attribute(AttributeProto {
                    g: Some(graph_with_initializer(external_tensor("subgraph-weight"))),
                    ..Default::default()
                })],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "subgraph-weight");
    }

    /// Nested two deep, so the recursion is covered rather than one level of
    /// unrolling that happens to look like it.
    #[test]
    fn a_nested_subgraph_tensor_is_refused() {
        let inner = GraphProto {
            node: vec![node_with_attribute(AttributeProto {
                g: Some(graph_with_initializer(external_tensor("deep-weight"))),
                ..Default::default()
            })],
            ..Default::default()
        };
        let model = ModelProto {
            graph: Some(GraphProto {
                node: vec![node_with_attribute(AttributeProto {
                    graphs: vec![inner],
                    ..Default::default()
                })],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_refused(&model, "deep-weight");
    }

    #[test]
    fn a_function_body_tensor_is_refused() {
        let model = ModelProto {
            functions: vec![FunctionProto {
                node: vec![node_with_attribute(AttributeProto {
                    t: Some(external_tensor("function-weight")),
                    ..Default::default()
                })],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_refused(&model, "function-weight");
    }

    #[test]
    fn a_training_graph_tensor_is_refused() {
        let model = ModelProto {
            training_info: vec![TrainingInfoProto {
                algorithm: Some(graph_with_initializer(external_tensor("training-weight"))),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_refused(&model, "training-weight");
    }

    /// `data_location` and `external_data` are independent fields. tract takes
    /// the external branch off the first alone, so a detector that only reads
    /// the second is narrower than the runtime it guards, and the reverse
    /// leaves a model that declares a location the runtime may later honor.
    #[test]
    fn external_data_without_the_location_marker_is_refused() {
        let model = ModelProto {
            graph: Some(graph_with_initializer(TensorProto {
                name: "marker-free".to_string(),
                dims: vec![1],
                data_type: tensor_proto::DataType::Float as i32,
                external_data: vec![StringStringEntryProto {
                    key: "location".to_string(),
                    value: "../../../../etc/shadow".to_string(),
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_refused(&model, "marker-free");
    }

    #[test]
    fn the_location_marker_without_an_entry_is_refused() {
        let model = ModelProto {
            graph: Some(graph_with_initializer(TensorProto {
                name: "entry-free".to_string(),
                dims: vec![1],
                data_type: tensor_proto::DataType::Float as i32,
                data_location: Some(tensor_proto::DataLocation::External as i32),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_refused(&model, "entry-free");
    }

    #[test]
    fn an_unnamed_tensor_is_refused_without_a_name_in_the_message() {
        let model = ModelProto {
            graph: Some(graph_with_initializer(TensorProto {
                dims: vec![1],
                data_type: tensor_proto::DataType::Float as i32,
                data_location: Some(tensor_proto::DataLocation::External as i32),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_refused(&model, "<unnamed>");
    }
}
