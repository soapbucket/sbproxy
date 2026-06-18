# Agent-detect fixtures

`ja4_catboost_fixture.onnx` is a synthetic CatBoost binary classifier
trained on the 14-feature JA4 vector used by `OnnxCatBoostScorer`.

CatBoost's default ONNX export appends an `ai.onnx.ml/ZipMap` output
adapter. `tract-onnx` 0.21 cannot type that sequence/map operator, so
the fixture keeps the exported `TreeEnsembleClassifier` and exposes the
raw `probability_tensor` output directly.
