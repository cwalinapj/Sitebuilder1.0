"""Simple HTML rendering without external templating libraries."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "templates"


def _template_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _replace_tokens(template: str, context: dict) -> str:
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", str(value))
    return rendered


def _profile_context(profile: dict) -> dict:
    return {
        "business_name": profile.get("business_name", ""),
        "phone": profile.get("phone", ""),
        "short_description": profile.get("short_description", ""),
        "long_description": profile.get("long_description", ""),
        "services_list": "".join(f"<li>{service}</li>" for service in profile.get("services", [])),
        "hours": json.dumps(profile.get("hours", {}), indent=2),
        "socials": json.dumps(profile.get("socials", {}), indent=2),
        "address": json.dumps(profile.get("address"), indent=2),
        "service_area": json.dumps(profile.get("service_area"), indent=2),
        "detected_category": profile.get("detected_category", "general"),
    }


def render_page(page_name: str, profile: dict) -> str:
    context = _profile_context(profile)
    category = profile.get("detected_category", "general")

    base_template = _template_text(TEMPLATES_DIR / "base.html")
    page_template = _template_text(TEMPLATES_DIR / "pages" / f"{page_name}.html")
    category_template = _template_text(TEMPLATES_DIR / "category" / f"{category}.html")

    page_content = _replace_tokens(page_template, {**context, "category_content": category_template})
    return _replace_tokens(
        base_template,
        {
            **context,
            "content": page_content,
            "page_title": f"{context['business_name']} | {page_name.title()}",
        },
    )
