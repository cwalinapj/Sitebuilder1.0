"""Build preview pages for current guided demo candidates."""

import json
from pathlib import Path

try:
    from generate_preview import generate_preview
except ModuleNotFoundError:  # pragma: no cover - import path for package-based tests
    from src.generate_preview import generate_preview

ROOT = Path(__file__).resolve().parent.parent
SESSION_STATE_PATH = ROOT / "session_state.json"
PREVIEW_DIR = ROOT / "site" / "preview"


def build_preview(session_state_path: Path | str = SESSION_STATE_PATH, output_dir: Path | str = PREVIEW_DIR) -> Path:
    state = json.loads(Path(session_state_path).read_text(encoding="utf-8"))
    return generate_preview(state.get("current_candidates", []), output_dir=output_dir)


def main() -> None:
    output_path = build_preview()
    print(f"Preview written to: {output_path}")


if __name__ == "__main__":
    main()
