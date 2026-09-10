"""Tests for :mod:`ulpf.parse.templates.miner` (Drain3 wrapper)."""

from __future__ import annotations

import uuid
from pathlib import Path

from ulpf.config.settings import Settings, StorageSettings
from ulpf.parse.templates.miner import TemplateMiner, TemplateMinerRegistry

_REPO = Path(__file__).resolve().parent.parent
_CONFIG = _REPO / "configs" / "drain3.ini"


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(state_path=tmp_path / "state"))


def _miner(tmp_path: Path, source_id: str = "fw1") -> TemplateMiner:
    return TemplateMiner(source_id, _settings(tmp_path), config_path=_CONFIG)


# --------------------------------------------------------------------------
# masking - the thing the whole module exists to get right
# --------------------------------------------------------------------------


def test_masks_ipv4_and_port_after_colon(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("User admin logged in from 192.168.1.5:22")
    assert result["template"] == "User admin logged in from <IP>:<PORT>"
    assert result["param_list"] == ["192.168.1.5", "22"]


def test_masks_ipv6(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Connection closed by 2001:db8::1")
    assert result["template"] == "Connection closed by <IP>"


def test_masks_mac_address(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Link failure on 00:1a:2b:3c:4d:5e")
    assert result["template"] == "Link failure on <MAC>"


def test_masks_uuid(tmp_path: Path) -> None:
    line = f"Session id={uuid.uuid4()} started"
    result = _miner(tmp_path).mine(line)
    assert result["template"] == "Session id=<UUID> started"


def test_masks_hex_string(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Firewall rule deadbeef01 matched")
    assert result["template"] == "Firewall rule <HEX> matched"


def test_masks_iso_timestamp(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("2026-09-05T10:00:00Z backup completed")
    assert result["template"] == "<TIMESTAMP> backup completed"


def test_masks_syslog_timestamp(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Sep 12 08:22:31 host kernel: link up")
    assert result["template"] == "<TIMESTAMP> host kernel: link up"


def test_masks_byte_count(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Sent 1024 bytes to peer")
    assert result["template"] == "Sent <BYTES> to peer"


def test_masks_quoted_string(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine('Policy "allow-web" matched')
    assert result["template"] == "Policy <QUOTED> matched"


def test_masks_plain_integer(tmp_path: Path) -> None:
    result = _miner(tmp_path).mine("Retrying after 3 attempts")
    assert result["template"] == "Retrying after <NUM> attempts"


# --------------------------------------------------------------------------
# 1000 lines, 5 shapes -> ~5 templates
# --------------------------------------------------------------------------


def _shape_lines(n_per_shape: int) -> list[str]:
    """``n_per_shape`` lines of each of 5 distinct shapes, fully interleaved.

    Every variable part is one this module's masks cover, so each shape masks
    down to exactly ONE literal string regardless of how many distinct raw
    values feed it - the shape count is what should drive the cluster count,
    not incidental variation Drain would otherwise have to discover itself.
    """
    lines: list[str] = []
    for i in range(n_per_shape):
        lines.append(f"User admin logged in from 192.168.1.{i % 254}:{2000 + i}")
        lines.append(f"Connection {i} closed after {100 + i} bytes")
        lines.append(f"Session id={uuid.uuid4()} expired")
        lines.append(f"Firewall rule {i:08x} matched host 00:1a:2b:3c:4d:{i % 100:02x}")
        lines.append(f'2026-09-{(i % 28) + 1:02d}T10:00:00Z backup completed "ok"')
    return lines


def test_1000_lines_of_5_shapes_produce_about_5_templates(tmp_path: Path) -> None:
    miner = _miner(tmp_path)
    lines = _shape_lines(200)  # 5 shapes * 200 = 1000
    assert len(lines) == 1000

    results = [miner.mine(line) for line in lines]

    templates = {r["template"] for r in results}
    assert len(templates) == 5
    assert results[-1]["cluster_count"] == 5

    created = [r for r in results if r["change_type"] == "cluster_created"]
    assert len(created) == 5  # exactly one per shape, the first time it's seen


def test_a_new_shape_creates_a_new_cluster(tmp_path: Path) -> None:
    miner = _miner(tmp_path)
    for line in _shape_lines(20):
        miner.mine(line)
    assert miner.mine("User admin logged in from 192.168.1.1:22")["cluster_count"] == 5

    result = miner.mine("Disk usage on /var/log reached 92%")

    assert result["change_type"] == "cluster_created"
    assert result["cluster_count"] == 6
    assert result["template"] == "Disk usage on /var/log reached <NUM>%"


# --------------------------------------------------------------------------
# state persists across a restart
# --------------------------------------------------------------------------


def test_state_persists_across_a_restart(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = TemplateMiner("fw1", settings, config_path=_CONFIG)
    for line in _shape_lines(20):
        first.mine(line)
    assert first.state_path.is_file()  # a cluster_created change autosaves

    # a brand-new process, same settings/source_id -> must resume, not restart
    second = TemplateMiner("fw1", settings, config_path=_CONFIG)
    result = second.mine("User admin logged in from 192.168.1.1:22")

    assert result["cluster_count"] == 5  # unchanged: no 6th cluster was created
    assert result["change_type"] == "none"  # this exact template already existed
    assert result["template"] == "User admin logged in from <IP>:<PORT>"


def test_flush_persists_even_when_the_last_line_changed_nothing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = TemplateMiner("fw1", settings, config_path=_CONFIG)
    first.mine("User admin logged in from 192.168.1.1:22")  # cluster_created -> autosaved
    second_result = first.mine("User admin logged in from 192.168.1.2:23")  # change_type="none"
    assert second_result["change_type"] == "none"
    first.flush()  # would be a no-op bug if flush didn't force a write here too

    second = TemplateMiner("fw1", settings, config_path=_CONFIG)
    result = second.mine("User admin logged in from 192.168.1.3:24")
    assert result["cluster_count"] == 1
    assert result["change_type"] == "none"


# --------------------------------------------------------------------------
# isolation between sources
# --------------------------------------------------------------------------


def test_registry_gives_one_isolated_miner_per_source_id(tmp_path: Path) -> None:
    registry = TemplateMinerRegistry(_settings(tmp_path), config_path=_CONFIG)

    fw = registry.get("fortigate_1")
    ids = registry.get("ids_1")
    assert fw is registry.get("fortigate_1")  # same instance on repeat lookup
    assert fw is not ids

    fw.mine("User admin logged in from 192.168.1.1:22")
    fw.mine("User admin logged in from 192.168.1.2:23")
    ids.mine("Alert triggered on rule 42")

    assert fw.mine("User admin logged in from 192.168.1.3:24")["cluster_count"] == 1
    assert ids.mine("Alert triggered on rule 43")["cluster_count"] == 1
    assert fw.state_path != ids.state_path


def test_registry_flush_all_persists_every_miner_created(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    registry = TemplateMinerRegistry(settings, config_path=_CONFIG)
    fw = registry.get("fortigate_1")
    fw.mine("User admin logged in from 192.168.1.1:22")
    fw.mine("User admin logged in from 192.168.1.2:23")  # change_type="none"
    registry.flush_all()

    reloaded = TemplateMiner("fortigate_1", settings, config_path=_CONFIG)
    result = reloaded.mine("User admin logged in from 192.168.1.3:24")
    assert result["cluster_count"] == 1
    assert result["change_type"] == "none"


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------


def test_unsafe_source_id_characters_are_sanitized_in_the_state_filename(tmp_path: Path) -> None:
    miner = TemplateMiner("fw/1:prod?", _settings(tmp_path), config_path=_CONFIG)
    miner.mine("hello world")
    assert miner.state_path.parent == tmp_path / "state"
    assert "/" not in miner.state_path.name and ":" not in miner.state_path.name
