"""Schema checks for business_profile.json."""

from __future__ import annotations

REQUIRED_KEYS = {
    "business_name": str,
    "phone": str,
    "location_type": str,
    "address": (dict, type(None)),
    "service_area": (dict, type(None)),
    "hours": dict,
    "services": list,
    "short_description": str,
    "long_description": str,
    "socials": dict,
    "images": list,
    "free_form": str,
    "detected_category": str,
}

ALLOWED_LOCATION_TYPES = {"storefront", "service_area", "both"}


def validate_profile(profile: dict) -> None:
    for key, expected_type in REQUIRED_KEYS.items():
        if key not in profile:
            raise ValueError(f"Missing required key: {key}")
        if not isinstance(profile[key], expected_type):
            raise ValueError(f"Invalid type for {key}: expected {expected_type}")

    if profile["location_type"] not in ALLOWED_LOCATION_TYPES:
        raise ValueError("location_type must be one of storefront|service_area|both")
