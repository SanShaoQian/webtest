import os
import re
from typing import Any, Dict, Optional

import requests


class GenAIError(Exception):
    pass


class GenAIQuotaError(GenAIError):
    def __init__(self, message: str, retry_after_seconds: Optional[int] = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


def _extract_retry_after_seconds(payload: Dict[str, Any]) -> Optional[int]:
    details = payload.get("error", {}).get("details", [])
    for item in details:
        retry_delay = item.get("retryDelay")
        if not retry_delay:
            continue
        match = re.match(r"^(\d+(?:\.\d+)?)s$", str(retry_delay).strip())
        if match:
            return int(float(match.group(1)))
    return None


def build_fallback_explanation(summary: Dict[str, Any]) -> str:
    stats = summary.get("stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        risk_line = "This file appears risky. At least one security engine marked it as malicious."
        action_line = "Do not open or run it. Delete it unless you trust the source and can verify it."
    elif suspicious > 0:
        risk_line = "This file is not clearly malicious, but some engines flagged it as suspicious."
        action_line = "Treat it cautiously. Avoid opening it on your main machine until validated."
    else:
        risk_line = "No engines reported malware in this scan result."
        action_line = "Risk is lower, but not zero. Only open if you trust the sender and context."

    detections = summary.get("detections", [])
    top_engines = [item.get("engine", "") for item in detections[:3] if item.get("engine")]
    engines_line = ""
    if top_engines:
        engines_line = f"Flagged by: {', '.join(top_engines)}."

    return (
        f"{risk_line}\n"
        f"Summary: malicious={malicious}, suspicious={suspicious}, harmless={harmless}, undetected={undetected}.\n"
        f"{engines_line}\n"
        f"Recommended next step: {action_line}"
    ).strip()


class GeminiClient:
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        self.api_key = api_key
        self.model = model

    def explain(self, summary: Dict[str, Any]) -> str:
        prompt = (
            "Explain this malware scan result for a non-technical person. "
            "Be concise, clear, and practical. Include whether they should be worried and next steps.\n\n"
            f"Scan summary: {summary}"
        )

        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            params={"key": self.api_key},
            json={
                "contents": [
                    {
                        "parts": [{"text": prompt}],
                    }
                ]
            },
            timeout=30,
        )

        if response.status_code == 429:
            payload = response.json() if response.content else {}
            retry_after_seconds = _extract_retry_after_seconds(payload)
            raise GenAIQuotaError("Gemini quota exceeded", retry_after_seconds=retry_after_seconds)

        if response.status_code >= 400:
            try:
                payload = response.json()
                provider_message = payload.get("error", {}).get("message")
            except Exception:
                provider_message = response.text
            raise GenAIError(f"Gemini request failed: {provider_message}")

        payload = response.json()
        candidates = payload.get("candidates", [])
        if not candidates:
            raise GenAIError("Gemini response did not contain candidates")

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "\n".join(part.get("text", "") for part in parts).strip()
        if not text:
            raise GenAIError("Gemini response did not include text")
        return text


def from_env() -> GeminiClient:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GenAIError("Missing GEMINI_API_KEY environment variable")

    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash").strip()
    return GeminiClient(api_key=api_key, model=model)

