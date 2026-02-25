# src/build_preview.py
from __future__ import annotations
import json, os
from src.render import read_text, render_template, write_text  # adjust import if needed
from src.schema import localbusiness_jsonld, year              # adjust import if needed

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "site", "preview")

def load_profile():
    with open(os.path.join(ROOT, "business_profile.json"), "r", encoding="utf-8") as f:
        return json.load(f)

def load_session():
    with open(os.path.join(ROOT, "session_state.json"), "r", encoding="utf-8") as f:
        return json.load(f)

def load_designs():
    with open(os.path.join(ROOT, "design_index", "designs.json"), "r", encoding="utf-8") as f:
        return {d["id"]: d for d in json.load(f)}

def load_palettes():
    with open(os.path.join(ROOT, "templates", "palettes.json"), "r", encoding="utf-8") as f:
        return json.load(f)

def phone_raw(p: str) -> str:
    return "".join([c for c in p if c.isdigit() or c == "+"])

def make_palette_css(vars_dict: dict) -> str:
    lines = [":root {"]
    for k, v in vars_dict.items():
        lines.append(f"  {k}: {v};")
    lines.append("}")
    return "\n".join(lines) + "\n"

def build_variant(variant_id: str):
    profile = load_profile()
    session = load_session()
    designs = load_designs()
    palettes = load_palettes()

    d = designs[variant_id]
    pal = palettes.get(d["palette"], {})

    base = read_text(os.path.join(ROOT, "templates", "base.html"))
    index_tpl = read_text(os.path.join(ROOT, "templates", "pages", "index.html"))
    cat_tpl = read_text(os.path.join(ROOT, "templates", "category", "general.html"))

    services = profile.get("services") or []
    services_li = "\n".join([f"<li>{s}</li>" for s in services])

    ctx = {
        "business_name": profile.get("business_name", ""),
        "phone": profile.get("phone", ""),
        "phone_raw": phone_raw(profile.get("phone", "")),
        "short_description": profile.get("short_description", ""),
        "meta_description": (profile.get("short_description", "")[:160]),
        "page_title": f"{profile.get('business_name','')} | {variant_id}",
        "hero_title": profile.get("business_name", ""),
        "services_li": services_li,
        "category_snippet": cat_tpl,
        "jsonld": localbusiness_jsonld(profile),
        "year": year(),
    }

    content = render_template(index_tpl, ctx)
    html = render_template(base, {**ctx, "content": content})

    # Write HTML
    out_dir = os.path.join(OUT, variant_id)
    write_text(os.path.join(out_dir, "index.html"), html)

    # Write palette override CSS (variant-specific)
    css_dir = os.path.join(out_dir, "assets")
    os.makedirs(css_dir, exist_ok=True)
    write_text(os.path.join(css_dir, "palette.css"), make_palette_css(pal))

    # Minimal stylesheet loader (variant can include palette.css after main css)
    # You can also modify base.html to always include /assets/palette.css if present.
    return out_dir

if __name__ == "__main__":
    session = load_session()
    candidates = session.get("current_candidates", [])
    for vid in candidates:
        print("Building:", vid, "->", build_variant(vid))
