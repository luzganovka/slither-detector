from flask import Flask, request, jsonify
from mythril.mythril import MythrilAnalyzer

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    bytecode = request.json["bytecode"]

    analyzer = MythrilAnalyzer(
        strategy="dfs",
        max_depth=22,
        execution_timeout=60
    )

    analyzer.load_from_bytecode(
        bytecode,
        bin_runtime=True
    )

    issues = analyzer.fire_lasers()

    result = []
    for issue in issues:
        result.append({
            "title": issue.title,
            "severity": issue.severity,
            "description": issue.description,
            "address": issue.address
        })

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
