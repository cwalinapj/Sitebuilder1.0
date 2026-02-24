import tempfile
import unittest
from pathlib import Path

from src.generate_preview import generate_preview


class GeneratePreviewTests(unittest.TestCase):
    def test_writes_preview_index_and_design_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = generate_preview(["modern-minimal-a", "bold-startup-a"], output_dir=tmp)
            self.assertTrue((Path(output_dir) / "index.html").exists())
            self.assertTrue((Path(output_dir) / "modern-minimal-a.html").exists())
            self.assertTrue((Path(output_dir) / "bold-startup-a.html").exists())


if __name__ == "__main__":
    unittest.main()
