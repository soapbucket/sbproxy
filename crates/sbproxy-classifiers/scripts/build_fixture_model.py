#!/usr/bin/env python3
"""Build a tiny ONNX classifier fixture for sbproxy-classifiers tests.

Produces:
  - tests/fixtures/tiny_classifier.onnx (a 2-class softmax over an 8-token
    vocabulary, no real semantics)
  - tests/fixtures/tiny_tokenizer.json (a 4-piece WordPiece tokenizer)

The fixture is deliberately microscopic - the goal is to exercise the
load + classify paths in the runtime, not to produce useful output.

Run with:
  uv run --with torch --with onnx --with tokenizers crates/sbproxy-classifiers/scripts/build_fixture_model.py

Outputs go under tests/fixtures/ relative to this script.
"""
from __future__ import annotations

import json
from pathlib import Path

import torch
import torch.nn as nn

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)


class TinyClassifier(nn.Module):
    """Embedding -> mean pool -> linear -> 2 classes.

    Inputs: input_ids (1, seq_len) int64, attention_mask (1, seq_len) int64.
    Output: logits (1, 2) float32.
    """

    def __init__(self, vocab_size: int = 8, embed_dim: int = 4, num_classes: int = 2):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.classifier = nn.Linear(embed_dim, num_classes)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        emb = self.embed(input_ids)
        # Masked mean pool.
        mask = attention_mask.unsqueeze(-1).float()
        pooled = (emb * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
        return self.classifier(pooled)


def build_model() -> Path:
    model = TinyClassifier()
    model.eval()
    dummy_ids = torch.tensor([[1, 2, 3, 4]], dtype=torch.long)
    dummy_mask = torch.tensor([[1, 1, 1, 1]], dtype=torch.long)
    out_path = OUT / "tiny_classifier.onnx"
    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask),
        out_path.as_posix(),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=14,
    )
    return out_path


def build_tokenizer() -> Path:
    """Hand-write a minimal HF tokenizer.json with a 4-piece WordPiece vocab."""
    tok = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [],
        "normalizer": {"type": "Lowercase"},
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": None,
        "decoder": None,
        "model": {
            "type": "WordLevel",
            "vocab": {
                "[UNK]": 0,
                "hello": 1,
                "world": 2,
                "ignore": 3,
                "previous": 4,
                "instructions": 5,
                "the": 6,
                "weather": 7,
            },
            "unk_token": "[UNK]",
        },
    }
    out_path = OUT / "tiny_tokenizer.json"
    out_path.write_text(json.dumps(tok, indent=2))
    return out_path


def main() -> None:
    model_path = build_model()
    tok_path = build_tokenizer()
    print(f"wrote {model_path}")
    print(f"wrote {tok_path}")


if __name__ == "__main__":
    main()
