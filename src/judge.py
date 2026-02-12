import requests
from .utils import audit


class PromptGuardDetector:
    def __init__(self, config=None):
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", False))
        self.model = self.config.get("model", "meta-llama/Prompt-Guard-86M")
        self.threshold = float(self.config.get("threshold", 0.8))
        self.fail_open = bool(self.config.get("fail_open", False))
        self.max_length = int(self.config.get("max_length", 512))
        self._classifier = None
        self._load_error = None

    def _suspicious_label(self, label):
        label_text = str(label).strip().lower()
        if not label_text:
            return False
        return any(
            token in label_text
            for token in ("inject", "jailbreak", "attack", "malicious", "unsafe")
        )

    def _normalize_prediction(self, raw):
        if isinstance(raw, list):
            if not raw:
                return {}
            first = raw[0]
            if isinstance(first, list):
                return first[0] if first else {}
            return first if isinstance(first, dict) else {}
        return raw if isinstance(raw, dict) else {}

    def _load_classifier(self):
        if self._classifier is not None or self._load_error is not None:
            return
        try:
            from transformers import pipeline
            self._classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.model,
            )
        except Exception as e:
            self._load_error = str(e)
            audit("PROMPT_GUARD", f"Unavailable: {e}", "WARNING")

    def _availability_result(self):
        reason = f"Prompt Guard unavailable: {self._load_error or 'unknown error'}"
        if self.fail_open:
            return {"ok": False, "safe": True, "reason": reason}
        return {"ok": False, "safe": False, "reason": reason}

    def scan_text(self, text, source="input"):
        if not self.enabled:
            return {
                "ok": True,
                "safe": True,
                "enabled": False,
                "reason": "Prompt Guard disabled",
            }

        self._load_classifier()
        if self._classifier is None:
            return self._availability_result()

        try:
            raw = self._classifier(
                str(text),
                truncation=True,
                max_length=self.max_length,
            )
        except Exception as e:
            self._load_error = str(e)
            audit("PROMPT_GUARD", f"Inference error: {e}", "WARNING")
            return self._availability_result()

        pred = self._normalize_prediction(raw)
        label = str(pred.get("label", "")).strip()
        score_raw = pred.get("score", 0.0)
        try:
            score = float(score_raw)
        except (TypeError, ValueError):
            score = 0.0

        suspicious = self._suspicious_label(label) and score >= self.threshold
        if suspicious:
            reason = (
                f"Prompt Guard flagged {source} as suspicious "
                f"(label={label}, score={score:.3f}, threshold={self.threshold:.3f})."
            )
            audit("PROMPT_GUARD", reason, "BLOCKED")
            return {
                "ok": True,
                "safe": False,
                "reason": reason,
                "label": label,
                "score": score,
            }

        audit(
            "PROMPT_GUARD",
            f"{source} classified as non-suspicious (label={label or 'unknown'}, score={score:.3f}).",
            "ALLOWED",
        )
        return {
            "ok": True,
            "safe": True,
            "label": label,
            "score": score,
            "reason": "Prompt Guard did not flag input",
        }


class AIJudge:
    def __init__(self, config=None):
        self.config = config or {}
        self.endpoint = self.config.get("endpoint", "http://localhost:11434/api/generate")
        self.model = self.config.get("model", "llama-guard3")
        self.fail_open = self.config.get("fail_open", False)
        self.risk_threshold = float(self.config.get("risk_threshold", 0.7))
        self.runtime_judge_threshold = float(self.config.get("runtime_judge_threshold", 0.4))
        self.prompt_guard = PromptGuardDetector(self.config.get("prompt_guard", {}))

    def call_ollama(self, prompt):
        """Raw call to Ollama API."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
            response = requests.post(self.endpoint, json=payload, timeout=5)
            return {"ok": True, "response": response.json().get("response", "").strip()}
        except Exception as e:
            audit("JUDGE_ERROR", f"Ollama unreachable: {e}", "WARNING")
            if self.fail_open:
                return {"ok": True, "response": "safe"}
            return {"ok": False, "response": "", "reason": "AI Judge unavailable"}

    def check_input_safety(self, text):
        """
        Layered input guard:
        1) Prompt Guard (optional) for prompt injection/jailbreak patterns.
        2) LlamaGuard for broad unsafe content checks.
        """
        prompt_guard_result = self.check_prompt_injection(text, source="user_input")
        if not prompt_guard_result.get("safe", True):
            reason = prompt_guard_result.get("reason", "Prompt Guard blocked input")
            audit("AI_JUDGE", f"Input blocked by Prompt Guard: {reason}", "BLOCKED")
            return {"safe": False, "reason": reason}

        # LlamaGuard 3 expects the raw input; it has internal templates.
        # We wrap it simply to define the task if needed, but raw usually works for basic checks.
        judge_result = self.call_ollama(text)
        if not judge_result.get("ok"):
            reason = judge_result.get("reason", "AI Judge unavailable")
            audit("AI_JUDGE", f"Input blocked: {reason}", "BLOCKED")
            return {"safe": False, "reason": reason}
        response = judge_result.get("response", "")
        
        # LlamaGuard output format is usually "safe" or "unsafe \n S{code}"
        if "unsafe" in response.lower():
            audit("AI_JUDGE", f"Input flagged as UNSAFE: {response}", "BLOCKED")
            return {"safe": False, "reason": f"LlamaGuard Flag: {response}"}
        
        audit("AI_JUDGE", "Input looks safe", "ALLOWED")
        return {"safe": True}

    def check_prompt_injection(self, text, source="input"):
        return self.prompt_guard.scan_text(text, source=source)

    def _looks_like_command_tool(self, tool):
        tool_name = str(tool).lower()
        return any(
            marker in tool_name
            for marker in ("subprocess", "os.system", "spawn", "exec", "popen")
        )

    def _extract_command_text(self, args):
        if isinstance(args, (list, tuple)):
            return " ".join(str(part) for part in args)
        return str(args)

    def _extract_url_text(self, args):
        if isinstance(args, dict):
            return str(args.get("url", ""))
        return str(args)

    def _heuristic_risk(self, tool, args):
        risk_score = 0.0
        reasons = []
        tool_name = str(tool)

        # 1. Command heuristics
        if self._looks_like_command_tool(tool_name):
            cmd = self._extract_command_text(args)
            if "rm " in cmd or "chmod" in cmd or "wget" in cmd:
                risk_score += 0.8
                reasons.append("Destructive or download command detected.")
            if "|" in cmd or ">" in cmd:
                risk_score += 0.5
                reasons.append("Shell redirection detected.")

        # 2. Network heuristics
        if tool_name in ("requests.get", "requests.post"):
            url = self._extract_url_text(args).lower()
            if "wallet" in url or "ledger" in url:
                risk_score += 0.9
                reasons.append("Crypto wallet access detected.")

        return risk_score, reasons

    def _build_runtime_action_prompt(self, tool, args, risk_score, reasons):
        reason_text = "; ".join(reasons) if reasons else "No heuristic reason provided."
        return (
            "You are a security policy judge for AI tool actions.\n"
            "Decide if the action is SAFE or UNSAFE.\n"
            "Return exactly one line starting with SAFE or UNSAFE, then a short reason.\n\n"
            f"Tool: {tool}\n"
            f"Args: {args}\n"
            f"Heuristic risk: {risk_score:.2f}\n"
            f"Heuristic reasons: {reason_text}\n"
        )

    def _parse_runtime_verdict(self, response_text):
        text = str(response_text).strip()
        lowered = text.lower()
        if "unsafe" in lowered:
            return False, text
        if "safe" in lowered:
            return True, text
        return False, f"Unparseable judge response: {text or 'empty response'}"

    def _judge_runtime_action(self, tool, args, risk_score, reasons):
        prompt = self._build_runtime_action_prompt(tool, args, risk_score, reasons)
        judge_result = self.call_ollama(prompt)
        if not judge_result.get("ok"):
            return {
                "ok": False,
                "safe": False,
                "reason": judge_result.get("reason", "AI Judge unavailable"),
            }

        safe, reason = self._parse_runtime_verdict(judge_result.get("response", ""))
        return {"ok": True, "safe": safe, "reason": reason}

    def evaluate_action(self, tool, args):
        """
        Runtime action safety check.
        Heuristics are used as a first-pass risk score.
        Medium/high-risk actions are adjudicated by the model.
        """
        risk_score, reasons = self._heuristic_risk(tool, args)
        if risk_score < self.runtime_judge_threshold:
            return {"safe": True, "needs_human": False}

        model_verdict = self._judge_runtime_action(tool, args, risk_score, reasons)
        high_risk = risk_score >= self.risk_threshold

        if not model_verdict["ok"]:
            if high_risk and not self.fail_open:
                return {
                    "safe": False,
                    "needs_human": True,
                    "reason": (
                        "High-risk action blocked because AI Judge is unavailable: "
                        f"{model_verdict['reason']}"
                    ),
                }
            return {
                "safe": True,
                "needs_human": False,
                "reason": (
                    "AI Judge unavailable, action allowed by fail-open/medium-risk policy: "
                    f"{model_verdict['reason']}"
                ),
            }

        if not model_verdict["safe"]:
            return {
                "safe": False,
                "needs_human": True,
                "reason": f"AI Judge blocked action ({risk_score:.2f}): {model_verdict['reason']}",
            }

        return {"safe": True, "needs_human": False}
