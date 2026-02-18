import os
import time
from typing import Any, Dict

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    def __init__(self, api_key: str, timeout_seconds: int = 120, poll_interval_seconds: int = 3):
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds

    @property
    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def upload_file(self, filename: str, file_bytes: bytes) -> str:
        files = {"file": (filename, file_bytes)}
        response = requests.post(
            f"{VT_BASE_URL}/files",
            headers=self._headers,
            files=files,
            timeout=30,
        )
        if response.status_code >= 400:
            raise VirusTotalError(f"VirusTotal upload failed: {response.text}")

        payload = response.json()
        analysis_id = payload.get("data", {}).get("id")
        if not analysis_id:
            raise VirusTotalError("VirusTotal response missing analysis id")
        return analysis_id

    def poll_analysis(self, analysis_id: str) -> Dict[str, Any]:
        deadline = time.time() + self.timeout_seconds

        while time.time() < deadline:
            response = requests.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers=self._headers,
                timeout=30,
            )
            if response.status_code >= 400:
                raise VirusTotalError(f"VirusTotal analysis check failed: {response.text}")

            payload = response.json()
            status = payload.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return payload

            time.sleep(self.poll_interval_seconds)

        raise VirusTotalError("Timed out waiting for VirusTotal analysis result")

    def summarize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        raw_results = attrs.get("results", {})

        detections = []
        for engine_name, result in raw_results.items():
            if result.get("category") == "malicious":
                detections.append(
                    {
                        "engine": engine_name,
                        "category": result.get("category"),
                        "result": result.get("result"),
                        "method": result.get("method"),
                    }
                )

        detections.sort(key=lambda item: item["engine"].lower())

        return {
            "status": attrs.get("status"),
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
            },
            "detections": detections,
            "analysis_id": payload.get("data", {}).get("id"),
        }


def from_env() -> VirusTotalClient:
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        raise VirusTotalError("Missing VT_API_KEY environment variable")

    timeout_seconds = int(os.getenv("VT_TIMEOUT_SECONDS", "120"))
    poll_interval_seconds = int(os.getenv("VT_POLL_INTERVAL_SECONDS", "3"))
    return VirusTotalClient(
        api_key=api_key,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )

