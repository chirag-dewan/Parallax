"""
PARALLAX Flask Application
"""

import logging

from flask import Flask, jsonify, render_template

from detection.pipeline import DetectionPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("parallax.app")

app = Flask(__name__)

pipeline = DetectionPipeline()


def load_traffic_data() -> None:
    """Load traffic.jsonl and run detection pipeline."""
    try:
        pipeline.register_default_detectors()
        pipeline.load_traffic("data/traffic.jsonl")
        pipeline.score_all()
        logger.info("Scored %d accounts", len(pipeline.assessments))
    except FileNotFoundError:
        logger.warning(
            "No traffic data found. Run: "
            "python traffic_generator.py --hours 48 --output data/traffic.jsonl"
        )


@app.route("/")
def dashboard():
    """Main dashboard view"""
    return render_template("dashboard.html")


@app.route("/api/accounts")
def get_accounts():
    """Returns list of all accounts with current scores."""
    account_list = []

    for account_id, assessment in pipeline.assessments.items():
        profile = pipeline.profiles[account_id]
        account_list.append(
            {
                "account_id": account_id,
                "archetype": profile.archetype,
                "total_events": profile.total_events,
                "account_age_days": profile.account_age_days,
                "score": assessment.composite_score,
                "threat_level": assessment.threat_level.value,
                "escalation_recommended": assessment.escalation_recommended,
                "triggered_rules": assessment.total_triggered_count,
            }
        )

    return jsonify(account_list)


@app.route("/api/account/<account_id>")
def get_account_detail(account_id):
    """Returns full detail for one account."""
    if account_id not in pipeline.profiles:
        return jsonify({"error": "Account not found"}), 404

    profile = pipeline.profiles[account_id]
    assessment = pipeline.assessments[account_id]

    rules = []
    for rule_id, result in assessment.results.items():
        rules.append(
            {
                "rule_id": result.rule_id.value,
                "rule_name": result.rule_name,
                "tier": result.tier.value,
                "score": result.score,
                "triggered": result.triggered,
                "confidence": result.confidence,
                "details": result.details,
            }
        )

    return jsonify(
        {
            "account_id": account_id,
            "archetype": profile.archetype,
            "account_age_days": profile.account_age_days,
            "total_events": profile.total_events,
            "score": assessment.composite_score,
            "threat_level": assessment.threat_level.value,
            "escalation_recommended": assessment.escalation_recommended,
            "tier1_triggered": assessment.tier1_triggered_count,
            "tier2_triggered": assessment.tier2_triggered_count,
            "top_signals": [
                {"rule_id": rid.value, "weighted_score": ws}
                for rid, ws in assessment.top_signals
            ],
            "rules": rules,
            "safety_triggers": profile.safety_trigger_count,
            "rate_limits": profile.rate_limit_hit_count,
            "api_requests": profile.api_request_count,
            "api_percentage": round(profile.api_ratio * 100, 2),
            "avg_input_tokens": round(profile.avg_input_tokens, 2),
            "avg_output_tokens": round(profile.avg_output_tokens, 2),
            "token_ratio": round(profile.token_ratio, 2),
        }
    )


if __name__ == "__main__":
    load_traffic_data()
    logger.info("PARALLAX Dashboard: http://localhost:5000")
    logger.info("API: http://localhost:5000/api/accounts")
    app.run(debug=True, host="0.0.0.0", port=5000)
