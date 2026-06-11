# Author: TK
# Date: 11-06-2026
# Purpose: Main dashboard to display attack and report.


from collections import Counter

from flask import Flask, jsonify, render_template, request

from config import DASHBOARD_HOST, DASHBOARD_PORT, DEBUG
from parser.log_parser import load_all_sessions, aggregate_by_ip
from parser.attack_classifier import AttackClassifier
from parser.profile_generator import generate_session_report, write_report
from enrichment.ioc_enricher import IOCEnricher


app = Flask(__name__)


def build_summary(enrich: bool = False) -> dict:
    sessions = load_all_sessions()
    classifier = AttackClassifier()

    technique_counter = Counter()
    tactic_counter = Counter()
    command_counter = Counter()
    ip_counter = Counter(s.get("peer_ip", "unknown") for s in sessions)

    for session in sessions:
        classification = classifier.classify_session(session)

        for technique in classification.get("techniques", []):
            key = f"{technique['id']} - {technique['name']}"
            technique_counter[key] += 1

        tactic_counter.update(classification.get("tactic_counts", {}))
        command_counter.update(session.get("commands", []))

    enriched_ips = []

    if enrich:
        enricher = IOCEnricher()

        for ip, count in ip_counter.most_common(10):
            info = enricher.enrich_ip(ip)
            info["session_count"] = count
            enriched_ips.append(info)

    return {
        "total_sessions": len(sessions),
        "unique_attackers": len(ip_counter),
        "total_commands": sum(len(s.get("commands", [])) for s in sessions),
        "top_ips": ip_counter.most_common(10),
        "top_ttps": technique_counter.most_common(10),
        "top_tactics": tactic_counter.most_common(10),
        "top_commands": command_counter.most_common(10),
        "enriched_ips": enriched_ips,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    enrich = request.args.get("enrich") == "1"
    return jsonify(build_summary(enrich=enrich))


@app.route("/api/sessions")
def api_sessions():
    sessions = load_all_sessions()
    return jsonify(sessions[-50:])


@app.route("/api/attackers")
def api_attackers():
    return jsonify(aggregate_by_ip(load_all_sessions()))


@app.route("/api/report/<session_id>", methods=["POST"])
def api_report(session_id):
    enrich = request.args.get("enrich") == "1"

    for session in load_all_sessions():
        if session.get("session_id") == session_id:
            report = generate_session_report(session, enrich=enrich)
            path = write_report(report)

            return jsonify(
                {
                    "saved_to": path,
                    "report": report,
                }
            )

    return jsonify({"error": "session not found"}), 404


def run_dashboard():
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=DEBUG,
        use_reloader=False,
    )
