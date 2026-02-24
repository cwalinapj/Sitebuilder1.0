import json
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_designs(designs_path: Path | None = None):
    path = designs_path or (_repo_root() / "design_index" / "designs.json")
    with Path(path).open("r", encoding="utf-8") as f:
        return {d["id"]: d for d in json.load(f)}


def generate_preview(design_ids: list[str], output_dir: Path | str | None = None, designs_by_id: dict | None = None) -> Path:
    designs_by_id = designs_by_id or load_designs()
    out = Path(output_dir) if output_dir else (_repo_root() / "site" / "preview")
    out.mkdir(parents=True, exist_ok=True)

    links = []
    for design_id in design_ids:
        design = designs_by_id.get(design_id)
        if not design:
            continue
        file_name = f"{design_id}.html"
        (out / file_name).write_text(
            "\n".join(
                [
                    "<!doctype html>",
                    "<html><head><meta charset='utf-8'><title>{}</title></head>".format(design.get("name", design_id)),
                    "<body>",
                    f"<h1>{design.get('name', design_id)}</h1>",
                    f"<p>Template: {design.get('template', 'unknown')} | Variant: {design.get('variant', 'unknown')}</p>",
                    f"<p>Tags: {', '.join(design.get('tags', []))}</p>",
                    "</body></html>",
                ]
            ),
            encoding="utf-8",
        )
        links.append(f"<li><a href='{file_name}'>{design.get('name', design_id)}</a></li>")

    (out / "index.html").write_text(
        "\n".join(
            [
                "<!doctype html>",
                "<html><head><meta charset='utf-8'><title>Preview</title></head>",
                "<body><h1>Design Preview</h1><ul>",
                *links,
                "</ul></body></html>",
            ]
        ),
        encoding="utf-8",
    )
    return out


if __name__ == "__main__":
    state_path = _repo_root() / "session_state.json"
    with state_path.open("r", encoding="utf-8") as f:
        state = json.load(f)

    output_path = generate_preview(state.get("current_candidates", []))
    print(f"Preview written to: {output_path}")
