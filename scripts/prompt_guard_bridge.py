#!/usr/bin/env python3

import argparse
import json
import sys


def _suspicious_label(label):
    label_text = str(label or "").strip().lower()
    return any(token in label_text for token in ("inject", "jailbreak", "attack", "malicious", "unsafe"))


def _normalize_prediction(raw):
    if isinstance(raw, list):
        if not raw:
            return {}
        first = raw[0]
        if isinstance(first, list):
            return first[0] if first else {}
        return first if isinstance(first, dict) else {}
    return raw if isinstance(raw, dict) else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Prompt Guard bridge (Transformers).")
    parser.add_argument("--text", required=True, help="Input text to classify.")
    parser.add_argument("--source", default="openclaw.bridge", help="Source label for audit context.")
    parser.add_argument("--model", default="meta-llama/Llama-Prompt-Guard-2-86M", help="HF model id.")
    parser.add_argument("--threshold", type=float, default=0.8, help="Suspicion threshold.")
    parser.add_argument("--max-length", type=int, default=512, help="Max tokenized length.")
    parser.add_argument("--fail-open", action="store_true", help="Return safe on model load/infer errors.")
    args = parser.parse_args()

    try:
        from transformers import pipeline  # noqa: WPS433

        classifier = pipeline(
            "text-classification",
            model=args.model,
            tokenizer=args.model,
        )
        raw = classifier(
            str(args.text),
            truncation=True,
            max_length=int(args.max_length),
        )
        pred = _normalize_prediction(raw)
        label = str(pred.get("label", "")).strip()
        score_raw = pred.get("score", 0.0)
        try:
            score = float(score_raw)
        except (TypeError, ValueError):
            score = 0.0
        suspicious = _suspicious_label(label) and score >= float(args.threshold)
        result = {
            "ok": True,
            "safe": not suspicious,
            "reason": (
                f"Prompt Guard flagged {args.source} as suspicious "
                f"(label={label}, score={score:.3f}, threshold={float(args.threshold):.3f})."
                if suspicious
                else "Prompt Guard did not flag input"
            ),
            "label": label or None,
            "score": score,
        }
        payload = {
            "ok": bool(result.get("ok", True)),
            "safe": bool(result.get("safe", True)),
            "reason": str(result.get("reason", "")),
            "label": result.get("label"),
            "score": result.get("score"),
        }
        print(json.dumps(payload, separators=(",", ":")))
        return 0
    except Exception as exc:  # pragma: no cover - runtime safety path
        payload = {
            "ok": False,
            "safe": bool(args.fail_open),
            "reason": f"Prompt guard bridge error: {exc}",
            "label": None,
            "score": None,
        }
        print(json.dumps(payload, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
