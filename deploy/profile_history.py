"""Compact history and read-only strategy suggestions for paired browser trials."""
import hashlib
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime

DAY = 86400
MAX_ROWS = 4096


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def shadow_choice(rows, now, profiles):
    """rows are newest first, timestamps describe sample starts."""
    recent = [row for row in rows if row[0] >= now - DAY]
    if not recent:
        return None, "expired"
    latest = recent[0]
    winners = {"only_first_observed": 0, "only_second_observed": 1}
    if latest[2] not in winners:
        return None, "latest_without_winner"
    if len(recent) < 2:
        return None, "need_second_session"
    previous = recent[1]
    # Allow the bounded browser trials to finish before treating a rerun as independent.
    if previous[1] + 120 > latest[0]:
        return None, "overlapping_trials"
    if previous[2] != latest[2]:
        return None, "results_disagree"
    return profiles[winners[latest[2]]], "repeated_advantage"


def record(path, network, comparison, now=None):
    now = time.time() if now is None else now
    results = {}
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE IF NOT EXISTS profile_trials (
            context TEXT NOT NULL, session TEXT NOT NULL, started REAL NOT NULL,
            last_sample REAL NOT NULL, outcome TEXT NOT NULL, evidence TEXT NOT NULL,
            PRIMARY KEY (context, session))""")
        db.execute("DELETE FROM profile_trials WHERE last_sample < ?", (now - 30 * DAY,))
        for service, trial in comparison["comparison"].items():
            pairs = trial["pairs"]
            times = [capture_timestamp(stamp) for pair in pairs for stamp in pair["utc"]]
            start, last = min(times), max(times)
            if last > now or start < now - 30 * DAY:
                raise ValueError("history accepts past trials within 30 days")
            reflectors = [{family: [c["target_sha256"], c["expected"]] for family, c in side.items()}
                          for side in pairs[0].get("egress", [])]
            context = digest([network, service, comparison["profiles"], comparison["browser_version"],
                              comparison["channel"], comparison["control_sha256"], reflectors,
                              comparison["video_id"] if service == "youtube" else None])
            session = digest(comparison["session"])
            evidence = digest(trial)
            stored = db.execute("SELECT evidence FROM profile_trials WHERE context=? AND session=?",
                                (context, session)).fetchone()
            if stored and stored[0] != evidence:
                raise ValueError("session already recorded with different evidence")
            if not stored:
                db.execute("INSERT INTO profile_trials VALUES (?,?,?,?,?,?)",
                           (context, session, start, last, trial["outcome"], evidence))
            rows = db.execute("""SELECT started,last_sample,outcome FROM profile_trials
                WHERE context=? ORDER BY last_sample DESC,session LIMIT 8""", (context,)).fetchall()
            profile, reason = shadow_choice(rows, now, comparison["profiles"])
            if not reflectors:
                profile, reason = None, "no_egress_control"
            results[service] = dict(suggested_profile=profile, reason=reason,
                                    recent_trials=[dict(first_sample=a, last_sample=b, outcome=o)
                                                   for a, b, o in rows])
        db.execute("""DELETE FROM profile_trials WHERE rowid IN
            (SELECT rowid FROM profile_trials ORDER BY last_sample DESC,rowid DESC LIMIT -1 OFFSET ?)""",
                   (MAX_ROWS,))
    return results


def capture_timestamp(stamp):
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("missing UTC offset")
    return parsed.timestamp()
