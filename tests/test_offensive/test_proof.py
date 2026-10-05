"""F1 — proof capture + access-signal detection (pure, no attack)."""

from arcanum.offensive.proof import detect_access, build_proof


def test_detect_access_session_signals():
    assert detect_access("[*] Meterpreter session 1 opened (1.2.3.4)")["level"] == "session"
    assert detect_access("Command shell session 2 opened")["level"] == "session"
    assert detect_access("uid=0(root) gid=0(root) groups=0(root)")["level"] == "session"


def test_detect_access_vuln_confirmed():
    assert detect_access("parameter 'id' is vulnerable")["level"] == "vuln_confirmed"
    assert detect_access("foo [high] [http] bar")["level"] == "vuln_confirmed"


def test_detect_access_none():
    assert detect_access("nothing interesting here") is None
    assert detect_access("") is None


def test_build_proof_masks_credentials_and_hashes_original():
    raw = "sshpass -p S3cretPass ssh root@10.0.0.1"
    p = build_proof("shell", raw, note="confirmed", deconfliction_tag="ARC-X")
    assert p["proof_type"] == "shell"
    assert "S3cretPass" not in p["evidence"]       # masked in stored evidence
    assert "***REDACTED***" in p["evidence"]
    assert len(p["sha256"]) == 64                   # hash over the ORIGINAL text
    assert p["deconfliction_tag"] == "ARC-X"
    assert p["summary"] == "confirmed"
