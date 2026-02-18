import os
from typing import Any, Dict

import requests


class GenAIError(Exception):
    pass


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

        if response.status_code >= 400:
            raise GenAIError(f"Gemini request failed: {response.text}")

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

