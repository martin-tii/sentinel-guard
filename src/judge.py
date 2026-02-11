import requests
import json
import logging
from .utils import audit

class AIJudge:
    def __init__(self, config=None):
        self.config = config or {}
        self.endpoint = self.config.get("endpoint", "http://localhost:11434/api/generate")
        self.model = self.config.get("model", "llama-guard3")
        self.fail_open = self.config.get("fail_open", False)

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

    def evaluate_action(self, tool, args):
        """
        Heuristic check for Tool usage. 
        (Running LLM for every tool call is slow, so we use logic first).
        """
        risk_score = 0
        reasons = []

        # 1. Shell Command Heuristics
        if tool == "subprocess.run" or tool == "os.system":
            cmd = str(args)
            if "rm " in cmd or "chmod" in cmd or "wget" in cmd:
                risk_score += 0.8
                reasons.append("Destructive or download command detected.")
            if "|" in cmd or ">" in cmd: # Redirection
                risk_score += 0.5
                reasons.append("Shell redirection detected.")

        # 2. Network Heuristics (Phishing / Crypto)
        if tool == "requests.get" or tool == "requests.post":
            url = args.get('url', '')
            if "wallet" in url or "ledger" in url:
                risk_score += 0.9
                reasons.append("Crypto wallet access detected.")
            
        if risk_score > self.config.get("risk_threshold", 0.7):
            return {
                "safe": False,
                "needs_human": True,
                "reason": f"High Risk Action ({risk_score}): {', '.join(reasons)}"
            }

        return {"safe": True, "needs_human": False}
