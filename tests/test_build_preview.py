import json
import tempfile
import unittest
from pathlib import Path

from src.build_preview import build_preview


class BuildPreviewTests(unittest.TestCase):
    def test_build_preview_uses_session_state_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_path = tmp_path / "session_state.json"
            output_dir = tmp_path / "site" / "preview"
            state_path.write_text(
                json.dumps({"current_candidates": ["modern-minimal-a", "bold-startup-a"]}),
                encoding="utf-8",
            )

            written_dir = build_preview(session_state_path=state_path, output_dir=output_dir)

            self.assertEqual(output_dir, written_dir)
            self.assertTrue((output_dir / "index.html").exists())
            self.assertTrue((output_dir / "modern-minimal-a.html").exists())
            self.assertTrue((output_dir / "bold-startup-a.html").exists())


if __name__ == "__main__":
    unittest.main()
