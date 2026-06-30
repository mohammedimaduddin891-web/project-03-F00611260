#!/usr/bin/env python3
"""impossible_travel.py — flag successive logins too far apart in space for the time.

Reference detector for Chapter 3 / Project 3 (Catch the Impostor).
Reads an auth log and reports any user whose two successful logins imply a
travel speed above a threshold no commercial flight can sustain.

Usage:
    python3 impossible_travel.py auth_events.csv --threshold-kmh 900

The math is geometry, not magic: great-circle (haversine) distance between the
two login locations, divided by the hours between them, gives an implied speed.
"""
import argparse
import csv
import math
from datetime import datetime


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance in kilometers between two lat/lon points."""
    r = 6371.0  # mean Earth radius, km
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def load_successful_logins(path):
    """Yield (ts, user, lat, lon, city) for successful login events only."""
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("event") == "login" and row.get("result") == "success":
                try:
                    ts = datetime.fromisoformat(row["ts"])
                    yield ts, row["user"], float(row["lat"]), float(row["lon"]), row["city"]
                except (ValueError, KeyError):
                    continue  # never crash on a malformed line


def detect(path, threshold_kmh):
    events = sorted(load_successful_logins(path), key=lambda e: (e[1], e[0]))
    alerts, prev = [], {}
    for ts, user, lat, lon, city in events:
        if user in prev:
            p_ts, p_lat, p_lon, p_city = prev[user]
            hours = (ts - p_ts).total_seconds() / 3600.0
            if hours > 0:
                km = haversine_km(p_lat, p_lon, lat, lon)
                kmh = km / hours
                if kmh > threshold_kmh:
                    alerts.append((user, p_city, city, hours, km, kmh))
        prev[user] = (ts, lat, lon, city)
    return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--threshold-kmh", type=float, default=900.0)
    args = ap.parse_args()
    alerts = detect(args.logfile, args.threshold_kmh)
    if not alerts:
        print("no impossible-travel events above threshold")
        return
    for user, src, dst, hrs, km, kmh in alerts:
        gap = f"{hrs * 60:.0f}min"
        print(f"ALERT  user={user}  {src}->{dst}  gap={gap}  "
              f"dist={km:.0f}km  implied={kmh:.0f} km/h  (>{args.threshold_kmh:.0f})")


if __name__ == "__main__":
    main()
