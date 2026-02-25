# src/recommend.py
from __future__ import annotations
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def load_designs():
    p = os.path.join(ROOT, "design_index", "designs.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def load_session():
    p = os.path.join(ROOT, "session_state.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def save_session(state: dict):
    p = os.path.join(ROOT, "session_state.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def score_design(design_id: str, taste: dict) -> float:
    s = 0.0
    # crude tag inference from id; replace with real tags later
    if "modern" in design_id: s += taste.get("modern", 0)
    if "minimal" in design_id: s += taste.get("minimal", 0)
    if "classic" in design_id: s += taste.get("professional", 0)
    if "luxury" in design_id: s += taste.get("professional", 0) * 0.6
    if "elegant" in design_id: s += taste.get("warm", 0) * 0.2
    return s

def recommend_next(n: int = 3):
    designs = load_designs()
    state = load_session()
    taste = state.get("taste_profile", {})
    shown = set(state.get("history", {}).get("shown_demos", []))

    scored = []
    for d in designs:
        if d["id"] in shown:
            continue
        scored.append((score_design(d["id"], taste), d["id"]))

    scored.sort(reverse=True)
    picks = [d for _, d in scored[:n]]

    state.setdefault("history", {}).setdefault("shown_demos", [])
    state["current_candidates"] = picks
    save_session(state)
    return picks

if __name__ == "__main__":
    print(recommend_next())
