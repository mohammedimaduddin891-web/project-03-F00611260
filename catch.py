#!/usr/bin/env python3
import argparse
import csv
import math
from collections import defaultdict, deque
from datetime import datetime, time, timedelta

EXPECTED_FIELDS = [
    "ts", "user", "event", "result", "role",
    "country", "city", "lat", "lon", "src_ip"
]

def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))

def parse_auth_events(path):
    events = []
    bad_lines = 0

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                if any(field not in row or row[field] == "" for field in EXPECTED_FIELDS):
                    raise ValueError("missing field")

                row["ts_dt"] = datetime.fromisoformat(row["ts"])
                row["lat_f"] = float(row["lat"])
                row["lon_f"] = float(row["lon"])
                events.append(row)

            except Exception:
                bad_lines += 1
                continue

    events.sort(key=lambda e: e["ts_dt"])
    return events, bad_lines

def detect_impossible_travel(events, threshold_kmh):
    alerts = []
    previous_success = {}

    for event in events:
        if event["event"] != "login" or event["result"] != "success":
            continue

        user = event["user"]

        if user in previous_success:
            prev = previous_success[user]
            hours = (event["ts_dt"] - prev["ts_dt"]).total_seconds() / 3600.0

            if hours > 0:
                km = haversine_km(prev["lat_f"], prev["lon_f"], event["lat_f"], event["lon_f"])
                speed = km / hours

                if speed > threshold_kmh:
                    alerts.append({
                        "ts": event["ts"],
                        "user": user,
                        "detector": "impossible_travel",
                        "detail": f'{prev["city"]}->{event["city"]} {km:.0f}km in {hours*60:.0f}min = {speed:.0f} km/h'
                    })

        previous_success[user] = event

    return alerts

def detect_off_hours_admin(events, business_start, business_end):
    alerts = []
    service_accounts = {e["user"] for e in events if e["role"] == "service"}

    start_t = time(business_start, 0)
    end_t = time(business_end, 0)

    for event in events:
        if event["role"] != "admin":
            continue

        if event["user"] in service_accounts:
            continue

        event_t = event["ts_dt"].time()
        in_hours = start_t <= event_t <= end_t

        if not in_hours:
            alerts.append({
                "ts": event["ts"],
                "user": event["user"],
                "detector": "off_hours_admin",
                "detail": f'{event["event"]} by admin at {event_t.strftime("%H:%M")}'
            })

    return alerts

def detect_bruteforce(events, failures_per_user, window_minutes):
    alerts = []
    failure_windows = defaultdict(deque)
    already_flagged = set()
    window = timedelta(minutes=window_minutes)

    for event in events:
        if event["event"] != "login" or event["result"] != "failure":
            continue

        user = event["user"]
        dq = failure_windows[user]
        dq.append(event)

        while dq and (event["ts_dt"] - dq[0]["ts_dt"]) > window:
            dq.popleft()

        if len(dq) >= failures_per_user and user not in already_flagged:
            alerts.append({
                "ts": dq[0]["ts"],
                "user": user,
                "detector": "brute_force",
                "detail": f'{len(dq)} failures for one account from {event["src_ip"]}'
            })
            already_flagged.add(user)

    return alerts

def detect_password_spray(events, users_per_ip, window_minutes):
    alerts = []
    failure_windows = defaultdict(deque)
    already_flagged = set()
    window = timedelta(minutes=window_minutes)

    for event in events:
        if event["event"] != "login" or event["result"] != "failure":
            continue

        ip = event["src_ip"]
        dq = failure_windows[ip]
        dq.append(event)

        while dq and (event["ts_dt"] - dq[0]["ts_dt"]) > window:
            dq.popleft()

        distinct_users = {x["user"] for x in dq}

        if len(distinct_users) >= users_per_ip:
            for item in dq:
                pair = (item["ts"], item["user"])
                if pair not in already_flagged:
                    alerts.append({
                        "ts": item["ts"],
                        "user": item["user"],
                        "detector": "password_spray",
                        "detail": f'failure from shared source IP {ip}'
                    })
                    already_flagged.add(pair)

    return alerts

def detect_privilege_escalation(events):
    alerts = []
    seen_roles = defaultdict(set)

    for event in events:
        user = event["user"]
        role = event["role"]

        if role not in seen_roles[user] and seen_roles[user]:
            alerts.append({
                "ts": event["ts"],
                "user": user,
                "detector": "privilege_escalation",
                "detail": f'new role observed: {role}'
            })

        seen_roles[user].add(role)

    return alerts

def load_ground_truth(path):
    truth = set()

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            truth.add((row["ts"], row["user"]))

    return truth

def score_alerts(alerts, truth):
    predicted = {(a["ts"], a["user"]) for a in alerts}

    true_positive = predicted & truth
    false_positive = predicted - truth
    false_negative = truth - predicted

    precision = len(true_positive) / len(predicted) if predicted else 0.0
    recall = len(true_positive) / len(truth) if truth else 0.0

    return precision, recall, sorted(false_positive), sorted(false_negative)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--truth", required=True)
    parser.add_argument("--threshold-kmh", type=float, default=900.0)
    parser.add_argument("--business-start", type=int, default=7)
    parser.add_argument("--business-end", type=int, default=21)
    parser.add_argument("--failures-per-user", type=int, default=5)
    parser.add_argument("--user-window-minutes", type=int, default=5)
    parser.add_argument("--spray-users-per-ip", type=int, default=5)
    parser.add_argument("--spray-window-minutes", type=int, default=10)
    args = parser.parse_args()

    events, bad_lines = parse_auth_events(args.logfile)

    alerts = []
    alerts.extend(detect_impossible_travel(events, args.threshold_kmh))
    alerts.extend(detect_off_hours_admin(events, args.business_start, args.business_end))
    alerts.extend(detect_bruteforce(events, args.failures_per_user, args.user_window_minutes))
    alerts.extend(detect_password_spray(events, args.spray_users_per_ip, args.spray_window_minutes))
    alerts.extend(detect_privilege_escalation(events))

    seen = set()
    deduped = []
    for alert in alerts:
        key = (alert["ts"], alert["user"], alert["detector"])
        if key not in seen:
            deduped.append(alert)
            seen.add(key)

    precision, recall, fps, fns = score_alerts(deduped, load_ground_truth(args.truth))

    print(f"parsed_events={len(events)} bad_lines={bad_lines}")
    print("ALERTS")
    for alert in sorted(deduped, key=lambda x: (x["ts"], x["user"], x["detector"])):
        print(f'{alert["ts"]}  {alert["user"]}  {alert["detector"]}  {alert["detail"]}')

    print()
    print(f"precision={precision:.3f}")
    print(f"recall={recall:.3f}")
    print(f"false_positives={fps}")
    print(f"false_negatives={fns}")

if __name__ == "__main__":
    main()
