import requests
from .utils import audit


class AIJudge:
    def __init__(self, config=None):
        self.config = config or {}
        self.endpoint = self.config.get("endpoint", "http://localhost:11434/api/generate")
        self.model = self.config.get("model", "llama-guard3")
        self.fail_open = self.config.get("fail_open", False)
        self.risk_threshold = float(self.config.get("risk_threshold", 0.7))
        self.runtime_judge_threshold = float(self.config.get("runtime_judge_threshold", 0.4))

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
        Asks LlamaGuard if the user input is safe.
        """
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
