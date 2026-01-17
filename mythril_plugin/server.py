import subprocess
import json
import tempfile
from flask import Flask, request, jsonify

app = Flask(__name__)


def run_mythril(bytecode: str) -> dict:
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".bin", delete=False) as f:
        f.write(bytecode)
        bytecode_file = f.name

    cmd = [
        "myth",
        "analyze",
        "-f",
        bytecode_file,
        "--bin",
        "--bin-runtime",
        "--execution-timeout",
        "60",
        "--max-depth",
        "22",
        "-o",
        "json"
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=bytecode.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Mythril timeout"
        }

    if proc.returncode != 0:
        return {
            "success": False,
            "error": proc.stderr.decode(errors="ignore")
        }

    try:
        return {
            "success": True,
            "raw": json.loads(proc.stdout.decode())
        }
    except json.JSONDecodeError:
        return {
            "success": False,"success": False,
            "error": "Failed to parse Mythril JSON output"
        }


def extract_issues(mythril_json: dict):
    """
    Normalize Mythril JSON to a stable format for Slither
    """
    issues = []

    for issue in mythril_json.get("issues", []):
        issues.append({
            "title": issue.get("title"),
            "severity": issue.get("severity"),
            "swc_id": issue.get("swc-id"),
            "description": issue.get("description"),
            "function": issue.get("function"),
            "address": issue.get("address")
        })

    return issues


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "bytecode" not in data:
        return jsonify({
            "success": False,
            "error": "Missing bytecode"
        }), 400

    result = run_mythril(data["bytecode"])
    print(f"DEBUG | mythril_answer: {result}", flush=True)


    if not result.get("success") or not result["raw"].get("success"):
        print(f"DEBUG | mythril error: {result.get('error')}", flush=True)
        return jsonify(result), 500

    issues = extract_issues(result["raw"])

    return jsonify({
        "success": True,
        "issues": issues
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
