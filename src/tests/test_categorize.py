import unittest

from src.categorize import categorize


class CategorizeTests(unittest.TestCase):
    def test_detects_plumber_from_free_form(self):
        profile = {"free_form": "We fix drains and plumbing leaks", "services": []}
        self.assertEqual(categorize(profile), "plumber")

    def test_detects_electrician_from_services(self):
        profile = {"free_form": "", "services": ["Panel upgrades", "Wiring repair"]}
        self.assertEqual(categorize(profile), "electrician")

    def test_website_text_can_drive_match(self):
        profile = {"free_form": "", "services": []}
        self.assertEqual(categorize(profile, website_text="Best restaurant menu and chef specials"), "restaurant")

    def test_defaults_to_general_without_keywords(self):
        profile = {"free_form": "Business consulting", "services": ["Coaching"]}
        self.assertEqual(categorize(profile), "general")


if __name__ == "__main__":
    unittest.main()
