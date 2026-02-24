import unittest

from src.recommend import recommend_next_designs, load_designs


class RecommendTests(unittest.TestCase):
    def test_returns_three_unique_recommendations(self):
        designs = load_designs()
        result = recommend_next_designs(
            taste_profile={"modern": 1.0, "minimal": 0.8, "professional": 0.7},
            history={"shown_demos": [], "likes": [], "dislikes": []},
            designs=designs,
            top_k=3,
        )
        self.assertEqual(3, len(result))
        self.assertEqual(3, len(set(result)))

    def test_excludes_shown_and_disliked(self):
        designs = load_designs()
        result = recommend_next_designs(
            taste_profile={"modern": 1.0, "minimal": 0.8, "professional": 0.7},
            history={
                "shown_demos": ["modern-minimal-a"],
                "likes": [],
                "dislikes": ["classic-corporate-a"],
            },
            designs=designs,
            top_k=3,
        )
        self.assertNotIn("modern-minimal-a", result)
        self.assertNotIn("classic-corporate-a", result)


if __name__ == "__main__":
    unittest.main()
