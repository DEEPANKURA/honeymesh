from __future__ import annotations

import os

import pytest

from app.config import HoneyMeshSettings, load_settings


def test_defaults_load() -> None:
    settings = load_settings()
    assert settings.environment.mode
    assert 0 <= settings.deception.max_level <= 5
    assert settings.detection.brute_force_threshold > 0
    assert len(settings.policies) >= 3
    assert set(settings.risk.weights) == {
        "recon",
        "credential",
        "web",
        "discovery",
        "lateral",
        "persistence",
    }


def test_env_override_beats_defaults(tmp_path) -> None:
    os.environ["HONEYMESH_DECEPTION__MAX_LEVEL"] = "3"
    try:
        settings = load_settings()
        assert settings.deception.max_level == 3
    finally:
        os.environ.pop("HONEYMESH_DECEPTION__MAX_LEVEL", None)


def test_unknown_risk_weight_rejected() -> None:
    with pytest.raises(ValueError, match="unknown risk weight"):
        HoneyMeshSettings.model_validate({"risk": {"weights": {"nope": 1.0}}})


def test_max_level_bounds() -> None:
    with pytest.raises(ValueError, match="max_level"):
        HoneyMeshSettings.model_validate({"deception": {"max_level": 9}})
