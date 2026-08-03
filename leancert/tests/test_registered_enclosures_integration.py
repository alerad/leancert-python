"""Opt-in Contract 2.8 integration against a profile-capable Bridge build."""

from __future__ import annotations

import os

import pytest

import leancert as lc
from leancert import ast


@pytest.mark.skipif(
    not all(
        os.environ.get(name)
        for name in (
            "LEANCERT_BRIDGE_PATH",
            "LEANCERT_ENCLOSURE_PROFILE",
            "LEANCERT_ENCLOSURE_PROJECT",
            "LEANCERT_ENCLOSURE_FUNCTION",
        )
    ),
    reason="Contract 2.8 integration environment is not configured",
)
def test_profiled_bridge_discovery_and_fixed_replay():
    with lc.Solver(
        binary_path=os.environ["LEANCERT_BRIDGE_PATH"],
        enclosure_profile=os.environ["LEANCERT_ENCLOSURE_PROFILE"],
        project_dir=os.environ["LEANCERT_ENCLOSURE_PROJECT"],
    ) as solver:
        function = solver.enclosures.function(os.environ["LEANCERT_ENCLOSURE_FUNCTION"])
        x = ast.var("x")
        result = solver.prove(function(x) <= 2, where={x: (0, 1)})
        assert isinstance(result, lc.VerifiedRegisteredEnclosure)
        assert solver.replay(result)[0]["replayed"] is True
