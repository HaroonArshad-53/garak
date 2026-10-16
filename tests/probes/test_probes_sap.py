import pytest

import garak._plugins
import garak.probes.base

SAP_PROBES = ("probes.sap.AttackPrompts",)


@pytest.mark.parametrize("probename", SAP_PROBES)
def test_sap_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe), "SAP probe should be a garak Probe"


@pytest.mark.parametrize("probename", SAP_PROBES)
def test_sap_prompts_count(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(p.prompts) >= 30, "SAP probe should ship a useful number of prompts"


@pytest.mark.parametrize("probename", SAP_PROBES)
def test_sap_prompts_wellformed(probename):
    p = garak._plugins.load_plugin(probename)
    for i, prompt in enumerate(p.prompts):
        assert isinstance(prompt, str), f"prompt {i} should be a string"
        assert len(prompt.strip()) > 0, f"prompt {i} should not be blank"
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "SAP prompts should be unique, no duplicates"


@pytest.mark.parametrize("probename", SAP_PROBES)
def test_sap_detector_configured(probename):
    p = garak._plugins.load_plugin(probename)
    assert (
        p.primary_detector == "mitigation.MitigationBypass"
    ), "SAP probe should use the mitigation bypass detector"
