import os
from http import HTTPStatus

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from .genai import GenAIError, GenAIQuotaError, build_fallback_explanation, from_env as gemini_from_env
from .virustotal import VirusTotalError, from_env as vt_from_env

ALLOWED_EXTENSIONS = {
    "txt",
    "js",
    "pdf",
    "zip",
    "exe",
    "dll",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
}


def create_app() -> Flask:
    load_dotenv()
    max_upload_mb = int(os.getenv("MAX_UPLOAD_MB", "16"))
    max_upload_bytes = max_upload_mb * 1024 * 1024

    app_root = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(app_root, "..", "templates")
    static_dir = os.path.join(app_root, "..", "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config["MAX_CONTENT_LENGTH"] = max_upload_bytes

    @app.get("/")
    def index():
        return render_template("index.html", max_upload_mb=max_upload_mb)

    @app.get("/health")
    def health():
        return {"ok": True}, HTTPStatus.OK

    @app.post("/api/scan")
    def scan_file():
        if "file" not in request.files:
            return jsonify({"error": "No file field in request"}), HTTPStatus.BAD_REQUEST

        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"error": "No file selected"}), HTTPStatus.BAD_REQUEST

        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({"error": "Invalid file name"}), HTTPStatus.BAD_REQUEST

        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension not in ALLOWED_EXTENSIONS:
            return (
                jsonify(
                    {
                        "error": "File type not allowed",
                        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
                    }
                ),
                HTTPStatus.BAD_REQUEST,
            )

        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"error": "Uploaded file is empty"}), HTTPStatus.BAD_REQUEST

        if len(file_bytes) > max_upload_bytes:
            return (
                jsonify({"error": f"File exceeds max size ({max_upload_mb} MB)"}),
                HTTPStatus.BAD_REQUEST,
            )

        try:
            vt_client = vt_from_env()
            analysis_id = vt_client.upload_file(filename=filename, file_bytes=file_bytes)
            analysis_payload = vt_client.poll_analysis(analysis_id)
            summary = vt_client.summarize(analysis_payload)
            summary["filename"] = filename
        except VirusTotalError as exc:
            return jsonify({"error": str(exc)}), HTTPStatus.BAD_GATEWAY
        except Exception:
            return jsonify({"error": "Unexpected server error during scan"}), HTTPStatus.INTERNAL_SERVER_ERROR

        return jsonify(summary), HTTPStatus.OK

    @app.post("/api/explain")
    def explain_result():
        payload = request.get_json(silent=True) or {}
        summary = payload.get("summary")
        if not summary:
            return jsonify({"error": "Missing summary in request body"}), HTTPStatus.BAD_REQUEST

        try:
            gemini_client = gemini_from_env()
            explanation = gemini_client.explain(summary)
        except GenAIQuotaError as exc:
            fallback_explanation = build_fallback_explanation(summary)
            warning = "Gemini quota is currently exceeded. Showing fallback explanation instead."
            if exc.retry_after_seconds:
                warning = f"Gemini quota is currently exceeded. Try again in about {exc.retry_after_seconds} seconds. Showing fallback explanation instead."
            return (
                jsonify(
                    {
                        "explanation": fallback_explanation,
                        "source": "fallback",
                        "warning": warning,
                    }
                ),
                HTTPStatus.OK,
            )
        except GenAIError as exc:
            return jsonify({"error": str(exc)}), HTTPStatus.BAD_GATEWAY
        except Exception:
            return jsonify({"error": "Unexpected server error while generating explanation"}), HTTPStatus.INTERNAL_SERVER_ERROR

        return jsonify({"explanation": explanation, "source": "gemini"}), HTTPStatus.OK

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": f"File too large. Maximum is {max_upload_mb} MB."}), HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    return app
