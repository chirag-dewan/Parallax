"""
PARALLAX Flask Application
"""

from flask import Flask, render_template, jsonify
import json
from collections import defaultdict

app = Flask(__name__)

# Load traffic data on startup
traffic_data = []
accounts = defaultdict(list)


def load_traffic_data():
    """Load traffic.jsonl into memory"""
    global traffic_data, accounts

    try:
        with open('data/traffic.jsonl', 'r') as f:
            for line in f:
                event = json.loads(line)
                traffic_data.append(event)
                accounts[event['account_id']].append(event)

        print(f"[+] Loaded {len(traffic_data):,} events from {len(accounts)} accounts")
    except FileNotFoundError:
        print("[!] No traffic data found. Run: python traffic_generator.py --hours 48 --output data/traffic.jsonl")


@app.route('/')
def dashboard():
    """Main dashboard view"""
    return render_template('dashboard.html')


@app.route('/api/accounts')
def get_accounts():
    """Returns list of all accounts with current scores"""
    account_list = []

    for account_id, events in accounts.items():
        account_list.append({
            'account_id': account_id,
            'archetype': events[0]['archetype'],
            'total_events': len(events),
            'account_age_days': events[0]['account_age_days'],
            'score': 0.0  # Placeholder for now
        })

    return jsonify(account_list)


@app.route('/api/account/<account_id>')
def get_account_detail(account_id):
    """Returns full detail for one account"""
    if account_id not in accounts:
        return jsonify({'error': 'Account not found'}), 404

    events = accounts[account_id]

    # Calculate basic stats
    total_events = len(events)
    safety_triggers = sum(1 for e in events if e['safety_filter_triggered'])
    rate_limits = sum(1 for e in events if e['rate_limit_hit'])
    api_requests = sum(1 for e in events if e['request_type'] == 'api')

    avg_input = sum(e['input_tokens'] for e in events) / total_events
    avg_output = sum(e['output_tokens'] for e in events) / total_events

    return jsonify({
        'account_id': account_id,
        'archetype': events[0]['archetype'],
        'account_age_days': events[0]['account_age_days'],
        'total_events': total_events,
        'safety_triggers': safety_triggers,
        'rate_limits': rate_limits,
        'api_requests': api_requests,
        'api_percentage': (api_requests / total_events * 100) if total_events > 0 else 0,
        'avg_input_tokens': avg_input,
        'avg_output_tokens': avg_output,
        'token_ratio': avg_output / avg_input if avg_input > 0 else 0,
        'score': 0.0  # Placeholder
    })


if __name__ == '__main__':
    load_traffic_data()
    print("\n" + "="*60)
    print("PARALLAX Dashboard")
    print("="*60)
    print("Dashboard: http://localhost:5000")
    print("API: http://localhost:5000/api/accounts")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
