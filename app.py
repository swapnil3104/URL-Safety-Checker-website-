import os
import json
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

from safety import assess_url_safety, ExternalCheckConfig


def create_app() -> Flask:
    load_dotenv()

    app = Flask(__name__, static_folder="static", template_folder="templates")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/check")
    def check_url():
        try:
            payload = request.get_json(silent=True) or {}
            url = (payload.get("url") or "").strip()
            if not url:
                return jsonify({"ok": False, "error": "Missing 'url' in JSON body."}), 400

            external_cfg = ExternalCheckConfig(
                google_safe_browsing_api_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"),
                virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
                enable_external_checks=(os.getenv("ENABLE_EXTERNAL_CHECKS", "true").lower() == "true"),
                request_timeout_seconds=int(os.getenv("EXTERNAL_REQUEST_TIMEOUT_SECONDS", "6")),
            )

            result = assess_url_safety(url, external_cfg)
            return jsonify({"ok": True, "data": result})
        except Exception as exc:
            # Do not leak stack traces to clients
            return jsonify({"ok": False, "error": f"Unexpected server error: {type(exc).__name__}"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)


