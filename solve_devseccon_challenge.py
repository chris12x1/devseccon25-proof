#!/usr/bin/env python3
# solve_devseccon_challenge.py
# Requires: pip install requests

import requests
import sys
import time
import json
import difflib
import re

BASE = "https://challenge.devseccon.com"
GET_URL = BASE + "/api/challenge"
POST_URL = BASE + "/api/challenge"

# Canonical OWASP Top-10 for LLMs (target order).
# If you want to change titles, edit these to match the OWASP canonical titles exactly.
CANONICAL = [
    "Prompt Injection",                      # LLM01
    "Sensitive Information Disclosure",     # LLM02
    "Supply Chain Vulnerabilities",         # LLM03
    "Data and Model Poisoning",              # LLM04
    "Improper Output Handling",             # LLM05
    "Excessive Agency",                     # LLM06
    "System Prompt Leakage",                # LLM07
    "Vector and Embedding Weaknesses",      # LLM08
    "Overreliance / Misinformation",        # LLM09
    "Unbounded Consumption / Model Theft"   # LLM10 (nomenclature varies across summaries)
]

# Helper normalization to reduce mismatch problems
def norm(s: str) -> str:
    s = s or ""
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9 ]+", " ", s)   # remove punctuation
    s = re.sub(r"\s+", " ", s)
    return s.lower()

def best_match_index(candidate, items_norm):
    # First try exact match
    n = norm(candidate)
    for i,it in enumerate(items_norm):
        if n == it:
            return i
    # Try substring containment
    for i,it in enumerate(items_norm):
        if n in it or it in n:
            return i
    # Fuzzy match fallback using difflib
    choices = items_norm
    matches = difflib.get_close_matches(n, choices, n=1, cutoff=0.6)
    if matches:
        return items_norm.index(matches[0])
    return None

def main():
    try:
        # Single-shot GET and POST; set short timeouts to try to keep total time < 3 seconds network permitting
        start = time.time()
        r = requests.get(GET_URL, timeout=2.0)
        r.raise_for_status()
        data = r.json()
        items = data.get("items")
        token = data.get("token")
        if not items or not isinstance(items, list) or not token:
            print("Unexpected GET response format:", data)
            return 1

        # normalized items for matching
        items_norm = [norm(x) for x in items]

        # build orderedList: orderedList[i] = shuffled position that has the item for correct position i
        ordered = []
        missing = []
        for canonical_title in CANONICAL:
            idx = best_match_index(canonical_title, items_norm)
            if idx is None:
                missing.append(canonical_title)
                ordered.append(None)
            else:
                ordered.append(idx)

        if missing:
            # try a second pass: attempt fuzzy across raw items if something didn't match
            for i, v in enumerate(ordered):
                if v is None:
                    # try matching relaxed canonical title parts
                    cand = CANONICAL[i]
                    # try splitting words and matching any token
                    tokens = [t for t in re.split(r"[ /]+", cand) if t]
                    found = None
                    for tok in tokens:
                        m = best_match_index(tok, items_norm)
                        if m is not None:
                            found = m
                            break
                    if found is not None:
                        ordered[i] = found

        # If still not all matched, we'll attempt a final heuristic: for any None choose a not-yet-used index (best-effort)
        used = set([x for x in ordered if x is not None])
        unused = [i for i in range(len(items)) if i not in used]
        for i,v in enumerate(ordered):
            if v is None and unused:
                ordered[i] = unused.pop(0)

        # sanity: ensure integers
        ordered = [int(x) for x in ordered]

        # Prepare payload and POST quickly
        payload = {"orderedList": ordered, "token": token}
        headers = {"Content-Type": "application/json"}

        # Make the POST. Use small timeout to try to stay inside the 3000ms window (network dependent).
        post_start = time.time()
        p = requests.post(POST_URL, headers=headers, json=payload, timeout=2.0)
        elapsed = (time.time() - start) * 1000.0
        # Print results
        print("GET items (shuffled):", items)
        print("Canonical target order:", CANONICAL)
        print("Computed orderedList:", ordered)
        print("Payload token:", token)
        print("POST status:", p.status_code)
        try:
            print("POST response:", p.json())
        except Exception:
            print("POST response text:", p.text)
        print(f"Total elapsed: {elapsed:.0f} ms (network-dependent)")
        return 0
    except Exception as e:
        print("Error:", e)
        return 2

if __name__ == "__main__":
    sys.exit(main())
