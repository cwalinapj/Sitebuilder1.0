import json
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_designs(designs_path: Path | None = None):
    path = designs_path or (_repo_root() / "design_index" / "designs.json")
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def _history_ids(history: dict, key: str) -> set[str]:
    values = history.get(key, []) or []
    ids = set()
    for item in values:
        if isinstance(item, dict) and item.get("design_id"):
            ids.add(item["design_id"])
        elif isinstance(item, str):
            ids.add(item)
    return ids


def recommend_next_designs(taste_profile: dict, history: dict, designs: list[dict] | None = None, top_k: int = 3) -> list[str]:
    designs = designs or load_designs()
    shown_ids = _history_ids(history, "shown_demos")
    liked_ids = _history_ids(history, "likes")
    disliked_ids = _history_ids(history, "dislikes")

    tag_by_id = {d["id"]: set(d.get("tags", [])) for d in designs}
    liked_tags = set().union(*(tag_by_id.get(did, set()) for did in liked_ids)) if liked_ids else set()

    candidates = []
    for design in designs:
        design_id = design.get("id")
        if not design_id or design_id in shown_ids or design_id in disliked_ids:
            continue

        tags = set(design.get("tags", []))
        taste_score = sum(float(taste_profile.get(tag, 0.0)) for tag in tags)
        like_score = len(tags & liked_tags) * 0.2
        candidates.append({"id": design_id, "tags": tags, "score": taste_score + like_score})

    candidates.sort(key=lambda item: (item["score"], item["id"]), reverse=True)

    selected = []
    selected_tags = []
    while candidates and len(selected) < top_k:
        if not selected:
            best = candidates.pop(0)
        else:
            best = max(
                candidates,
                key=lambda item: item["score"] - 0.1 * max((len(item["tags"] & t) for t in selected_tags), default=0),
            )
            candidates.remove(best)
        selected.append(best["id"])
        selected_tags.append(best["tags"])

    return selected


if __name__ == "__main__":
    state_path = _repo_root() / "session_state.json"
    with state_path.open("r", encoding="utf-8") as f:
        state = json.load(f)

    state["current_candidates"] = recommend_next_designs(
        taste_profile=state.get("taste_profile", {}),
        history=state.get("history", {}),
    )

    with state_path.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    print("Recommended:", ", ".join(state["current_candidates"]))
