"""F1 — proof capture + access-signal detection (pure, no attack)."""

import pytest

from arcanum.offensive.proof import detect_access, build_proof, capture_screenshot


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


@pytest.mark.asyncio
async def test_capture_screenshot_captured_with_injected_shooter(tmp_path):
    async def shooter(url, path):
        with open(path, "wb") as fh:
            fh.write(b"\x89PNG\r\n stub image bytes")
        return True
    res = await capture_screenshot("http://host.docker.internal:8080/app", tmp_path,
                                   shooter=shooter, deconfliction_tag="ARC-1")
    assert res["status"] == "captured" and res["proof_type"] == "screenshot"
    assert len(res["sha256"]) == 64 and res["path"].endswith(".png")
    assert res["deconfliction_tag"] == "ARC-1"


@pytest.mark.asyncio
async def test_capture_screenshot_unavailable_is_honest(tmp_path):
    async def shooter(url, path):
        return False  # e.g. Playwright not installed
    res = await capture_screenshot("http://t", tmp_path, shooter=shooter)
    assert res["status"] == "unavailable" and res["proof_type"] == "screenshot"
    assert "path" not in res  # never claims an image it did not capture
