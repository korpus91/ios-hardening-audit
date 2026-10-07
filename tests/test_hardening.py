import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import hardening as h  # noqa: E402


def rules(name):
    return {x.rule for x in h.audit_config(name, (HERE / f"{name}.cfg").read_text())}


def test_hardened_config_is_clean():
    assert rules("hard-sw1") == set()


def test_weak_config_core_findings():
    r = rules("weak-sw1")
    for rule in ("H01", "H02", "H04", "H07", "H10", "H11", "H13", "H14", "H15", "H16", "H17", "H18", "H19", "H21"):
        assert rule in r, rule


def test_secrets_are_redacted():
    text = "\n".join(x.evidence for x in h.audit_config("weak-sw1", (HERE / "weak-sw1.cfg").read_text()))
    assert "admin123" not in text and "wr1te" not in text and "cisco123" not in text


def test_md5_enable_secret_is_medium():
    f = h.audit_config("x", "enable secret 5 $1$abcd$efgh\n")
    assert any(x.rule == "H03" and x.severity == "medium" for x in f)


def test_cli_exit_codes(tmp_path):
    assert h.main([str(HERE / "hard-sw1.cfg")]) == 0
    out = tmp_path / "f.json"
    assert h.main([str(HERE / "weak-sw1.cfg"), "--json", str(out)]) == 1
    assert out.exists()