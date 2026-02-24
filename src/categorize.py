"""Business category heuristics."""

from __future__ import annotations

CATEGORY_KEYWORDS = {
    "plumber": ["plumb", "drain", "pipe", "leak", "water heater", "sewer"],
    "electrician": ["electric", "wiring", "breaker", "panel", "lighting", "outlet"],
    "barber": ["barber", "fade", "beard", "haircut", "trim", "shave"],
    "restaurant": ["restaurant", "menu", "dine", "food", "chef", "catering"],
}

CATEGORY_ORDER = ["plumber", "electrician", "barber", "restaurant"]


def categorize(profile: dict, website_text: str | None = None) -> str:
    text_parts = [profile.get("free_form", "")]
    text_parts.extend(profile.get("services", []))
    if website_text:
        text_parts.append(website_text)

    combined_text = " ".join(str(part) for part in text_parts).lower()

    scores = {category: 0 for category in CATEGORY_ORDER}
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in combined_text:
                scores[category] += 1

    best_category = "general"
    best_score = 0
    for category in CATEGORY_ORDER:
        score = scores[category]
        if score > best_score:
            best_score = score
            best_category = category

    return best_category if best_score > 0 else "general"
