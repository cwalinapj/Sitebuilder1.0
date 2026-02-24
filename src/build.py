"""Static site build script."""

from __future__ import annotations

import json
from pathlib import Path

from categorize import categorize
from render import render_page
from schema import validate_profile

ROOT = Path(__file__).resolve().parent.parent
PROFILE_PATH = ROOT / "business_profile.json"
SITE_DIR = ROOT / "site"
ASSETS_DIR = SITE_DIR / "assets"

PAGE_OUTPUTS = {
    "index": SITE_DIR / "index.html",
    "about": SITE_DIR / "about" / "index.html",
    "services": SITE_DIR / "services" / "index.html",
    "contact": SITE_DIR / "contact" / "index.html",
}

STYLE_CSS = """body { font-family: Arial, sans-serif; margin: 0; color: #222; background: #f7f7f7; }
header, main, footer { max-width: 960px; margin: 0 auto; padding: 1rem; }
header { background: #fff; border-bottom: 1px solid #ddd; }
nav a { margin-right: 0.8rem; color: #004680; text-decoration: none; }
main { background: #fff; margin-top: 1rem; border: 1px solid #eee; border-radius: 8px; }
footer { font-size: 0.9rem; color: #555; }
"""


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_schema(profile: dict) -> dict:
    return {
        "@context": "https://schema.org",
        "@type": "LocalBusiness",
        "name": profile["business_name"],
        "telephone": profile["phone"],
        "description": profile["short_description"],
        "areaServed": profile.get("service_area"),
        "address": profile.get("address"),
    }


def main() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    validate_profile(profile)

    profile["detected_category"] = categorize(profile)
    PROFILE_PATH.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")

    for page, destination in PAGE_OUTPUTS.items():
        _write_text(destination, render_page(page, profile))

    base_url = profile.get("socials", {}).get("website", "https://example.com").rstrip("/")
    sitemap = "\n".join(
        [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
            f"  <url><loc>{base_url}/</loc></url>",
            f"  <url><loc>{base_url}/about/</loc></url>",
            f"  <url><loc>{base_url}/services/</loc></url>",
            f"  <url><loc>{base_url}/contact/</loc></url>",
            "</urlset>",
        ]
    )

    _write_text(SITE_DIR / "sitemap.xml", sitemap)
    _write_text(SITE_DIR / "robots.txt", "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n")
    _write_text(ASSETS_DIR / "style.css", STYLE_CSS)
    _write_text(ASSETS_DIR / "business-schema.json", json.dumps(_build_schema(profile), indent=2) + "\n")


if __name__ == "__main__":
    main()
