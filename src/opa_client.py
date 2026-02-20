import time
from urllib.parse import urljoin

import requests


class OPAClientError(RuntimeError):
    def __init__(self, message, *, code="opa_error", retryable=True):
        super().__init__(message)
        self.code = str(code)
        self.retryable = bool(retryable)


class OPAClient:
    def __init__(self, base_url, decision_path, timeout_ms=1500, max_retries=1):
        self.base_url = str(base_url or "http://127.0.0.1:8181").rstrip("/")
        self.decision_path = str(decision_path or "/v1/data/sentinel/authz/decision")
        self.timeout_seconds = max(0.05, float(timeout_ms) / 1000.0)
        self.max_retries = max(0, int(max_retries))

    def _endpoint(self):
        return urljoin(self.base_url + "/", self.decision_path.lstrip("/"))

    def decide(self, input_payload):
        endpoint = self._endpoint()
        body = {"input": input_payload}
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(endpoint, json=body, timeout=self.timeout_seconds)
                if response.status_code >= 500:
                    raise OPAClientError(
                        f"OPA server error ({response.status_code})",
                        code="opa_server_error",
                        retryable=True,
                    )
                if response.status_code >= 400:
                    raise OPAClientError(
                        f"OPA request rejected ({response.status_code})",
                        code="opa_bad_request",
                        retryable=False,
                    )

                payload = response.json()
                result = payload.get("result")
                if not isinstance(result, dict):
                    raise OPAClientError(
                        "OPA response missing 'result' object.",
                        code="opa_invalid_response",
                        retryable=False,
                    )

                allow = result.get("allow")
                if not isinstance(allow, bool):
                    raise OPAClientError(
                        "OPA response missing boolean 'allow'.",
                        code="opa_invalid_response",
                        retryable=False,
                    )

                reason = str(result.get("reason", "")).strip()
                tags = result.get("tags")
                if not isinstance(tags, list):
                    tags = []
                tags = [str(tag) for tag in tags if str(tag).strip()]
                return {
                    "allow": allow,
                    "reason": reason,
                    "tags": tags,
                }
            except requests.Timeout as exc:
                last_error = OPAClientError(
                    f"OPA timeout: {exc}", code="opa_timeout", retryable=True
                )
            except requests.RequestException as exc:
                last_error = OPAClientError(
                    f"OPA connection error: {exc}", code="opa_unreachable", retryable=True
                )
            except ValueError as exc:
                last_error = OPAClientError(
                    f"OPA invalid JSON response: {exc}",
                    code="opa_invalid_response",
                    retryable=False,
                )
            except OPAClientError as exc:
                last_error = exc

            if attempt < self.max_retries and getattr(last_error, "retryable", False):
                time.sleep(0.05)
                continue
            break

        raise last_error or OPAClientError("Unknown OPA client error.")
