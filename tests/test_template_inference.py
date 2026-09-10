"""Tests for :mod:`ulpf.parse.templates.inference` — synthetic firewall-like lines."""

from __future__ import annotations

from ulpf.parse.templates.inference import infer_field_types

# --------------------------------------------------------------------------
# one full firewall-shaped template, every rule at once


_FULL_TEMPLATE = (
    "<TIMESTAMP> srcip=<IP> srcport=<NUM> dstip=<IP> dstport=<NUM> "
    "proto=<NUM> action=<QUOTED> sentbyte=<NUM> rcvdbyte=<NUM> "
    "srcintf=<*> dstintf=<*>"
)


def _full_samples(n: int) -> list[list[str]]:
    """``n`` synthetic FortiGate-like rows matching ``_FULL_TEMPLATE``'s 11 positions."""
    rows = []
    for i in range(n):
        rows.append(
            [
                f"2026-09-{i % 28 + 1:02d}T10:00:{i % 60:02d}Z",
                f"10.0.0.{i % 254 + 1}",
                str(40000 + i),
                f"198.51.100.{i % 5 + 1}",
                "443" if i % 2 == 0 else "80",
                "6" if i % 3 else "17",
                '"deny"' if i % 4 == 0 else '"accept"',
                str(500 + i * 137),  # grows, varied, large
                str(300 + i * 89),
                f"port{i % 2 + 1}",
                f"port{i % 2 + 3}",
            ]
        )
    return rows


def _by_position(guesses: list[dict]) -> dict[int, dict]:
    return {g["position"]: g for g in guesses}


def test_full_firewall_line_every_position_inferred_correctly() -> None:
    guesses = infer_field_types(_FULL_TEMPLATE, _full_samples(30))
    assert len(guesses) == 11
    by_pos = _by_position(guesses)

    assert by_pos[0]["inferred_semantic"] == "timestamp"
    assert by_pos[1]["inferred_semantic"] == "source_ip"
    assert by_pos[2]["inferred_semantic"] == "port"  # adjacent to srcip
    assert by_pos[3]["inferred_semantic"] == "destination_ip"
    assert by_pos[4]["inferred_semantic"] == "port"  # adjacent to dstip
    assert by_pos[5]["inferred_semantic"] == "protocol"
    assert by_pos[6]["inferred_semantic"] == "action"
    assert by_pos[7]["inferred_semantic"] == "byte_count"
    assert by_pos[8]["inferred_semantic"] == "byte_count"
    assert by_pos[9]["inferred_semantic"] == "interface_name"
    assert by_pos[10]["inferred_semantic"] == "interface_name"

    # every position's mask_type is echoed back from the template, unmodified
    assert [g["mask_type"] for g in guesses] == [
        "TIMESTAMP",
        "IP",
        "NUM",
        "IP",
        "NUM",
        "NUM",
        "QUOTED",
        "NUM",
        "NUM",
        "*",
        "*",
    ]
    # every rule held consistently across a clean sample set
    assert all(g["confidence"] == 1.0 for g in guesses)
    assert all(1 <= len(g["example_values"]) <= 5 for g in guesses)


# --------------------------------------------------------------------------
# ip_address / source_ip / destination_ip ordering


def test_first_ip_is_source_second_is_destination_third_stays_generic() -> None:
    template = "a=<IP> b=<IP> c=<IP>"
    samples = [["10.0.0.1", "198.51.100.1", "203.0.113.1"] for _ in range(10)]
    guesses = infer_field_types(template, samples)
    semantics = [g["inferred_semantic"] for g in guesses]
    assert semantics == ["source_ip", "destination_ip", "ip_address"]


def test_ipv6_addresses_are_also_recognized() -> None:
    template = "from <IP>"
    samples = [["2001:db8::" + str(i)] for i in range(10)]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "source_ip"
    assert guess["confidence"] == 1.0


def test_a_bare_integer_is_not_mistaken_for_an_ip() -> None:
    # ipaddress.ip_address("6") would happily parse as 0.0.0.6 - must be rejected
    template = "proto=<NUM>"
    samples = [["6"], ["17"], ["6"], ["17"], ["6"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] != "ip_address"


# --------------------------------------------------------------------------
# protocol


def test_low_cardinality_iana_numbers_are_protocol() -> None:
    template = "proto <NUM>"
    samples = [["6"], ["17"], ["6"], ["6"], ["17"]]  # only 2 distinct values -> full confidence
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "protocol"
    assert guess["confidence"] == 1.0


def test_protocol_confidence_is_slightly_discounted_with_more_distinct_values() -> None:
    template = "proto <NUM>"
    samples = [["6"], ["17"], ["6"], ["6"], ["1"], ["17"]]  # 3 distinct IANA values
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "protocol"
    assert 0.8 <= guess["confidence"] < 1.0


def test_high_cardinality_numbers_are_not_protocol_even_if_some_are_iana() -> None:
    # ports/ids that happen to occasionally land on 6 or 17 must not be swept up
    template = "id <NUM>"
    samples = [[str(v)] for v in range(1, 40)]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] != "protocol"


# --------------------------------------------------------------------------
# action


def test_closed_verdict_word_set_is_action() -> None:
    template = "verdict=<*>"
    samples = [["allow"], ["deny"], ["accept"], ["drop"], ["block"], ["allow"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "action"
    assert guess["confidence"] == 1.0


def test_action_words_are_matched_case_and_quote_insensitively() -> None:
    template = "action=<QUOTED>"
    samples = [['"DENY"'], ["'Accept'"], ['"deny"'], ["ALLOW"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "action"


# --------------------------------------------------------------------------
# timestamp


def test_iso_timestamps_are_recognized() -> None:
    template = "at <TIMESTAMP>"
    samples = [[f"2026-09-{d:02d}T10:00:00Z"] for d in range(1, 15)]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "timestamp"


def test_syslog_style_timestamps_are_recognized() -> None:
    template = "<TIMESTAMP> host"
    samples = [["Sep 12 08:22:31"], ["Sep 13 09:00:00"], ["Sep 14 23:59:59"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "timestamp"


def test_a_bare_epoch_integer_is_not_a_timestamp_unless_the_mask_says_so() -> None:
    # otherwise every large growing byte counter would misclassify as a timestamp
    template = "count=<NUM>"
    samples = [[str(1_700_000_000 + i)] for i in range(10)]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] != "timestamp"


# --------------------------------------------------------------------------
# port (adjacency requirement)


def test_port_range_int_adjacent_to_ip_is_a_port() -> None:
    template = "host <IP>:<NUM>"
    samples = [[f"10.0.0.{i}", str(1024 + i)] for i in range(10)]
    guesses = infer_field_types(template, samples)
    assert guesses[1]["inferred_semantic"] == "port"


def test_port_range_int_not_adjacent_to_any_ip_is_not_classified_as_port() -> None:
    # same 0-65535 shape, but nothing IP-like anywhere in the template
    template = "value=<NUM>"
    samples = [[str(100 + i)] for i in range(5)]  # low cardinality, low magnitude
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] != "port"


def test_srcport_and_dstport_both_resolve_via_their_own_ip_neighbour() -> None:
    template = "<IP>:<NUM> -> <IP>:<NUM>"
    samples = [[f"10.0.0.{i}", str(50000 + i), "198.51.100.9", "443"] for i in range(10)]
    guesses = infer_field_types(template, samples)
    assert [g["inferred_semantic"] for g in guesses] == [
        "source_ip",
        "port",
        "destination_ip",
        "port",
    ]


# --------------------------------------------------------------------------
# byte_count


def test_large_varied_growing_integers_are_byte_count() -> None:
    template = "bytes=<NUM>"
    samples = [[str(1000 + i * 250)] for i in range(20)]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "byte_count"


def test_small_or_constant_integers_are_not_byte_count() -> None:
    template = "flag=<NUM>"
    samples = [["1"]] * 10
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] != "byte_count"


# --------------------------------------------------------------------------
# interface_name


def test_low_cardinality_strings_after_interface_keyword_are_interface_name() -> None:
    template = "on interface <*>"
    samples = [["eth0"], ["eth1"], ["eth0"], ["eth2"], ["eth1"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "interface_name"


def test_intf_abbreviation_is_also_recognized() -> None:
    template = "srcintf=<*>"
    samples = [["port1"], ["port2"], ["port1"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "interface_name"


def test_numeric_values_after_a_port_keyword_are_not_interface_name() -> None:
    # "port" is ambiguous: a real port NUMBER next to the word "port" must not
    # be swept into interface_name just because the keyword matched
    template = "port <IP>:<NUM>"
    samples = [[f"10.0.0.{i}", str(1024 + i)] for i in range(10)]
    guesses = infer_field_types(template, samples)
    assert guesses[1]["inferred_semantic"] == "port"


def test_an_earlier_positions_keyword_does_not_bleed_into_the_next_position() -> None:
    # regression: "interface <*> session <HEX>" - the HEX position must not
    # inherit "interface" from the PREVIOUS wildcard's preceding text
    template = "on interface <*> session <HEX>"
    samples = [["eth0", "a1b2c3d4e5"], ["eth1", "a1b2c3d4e5"], ["eth0", "a1b2c3d4e5"]]
    guesses = infer_field_types(template, samples)
    assert guesses[0]["inferred_semantic"] == "interface_name"
    assert guesses[1]["inferred_semantic"] != "interface_name"


# --------------------------------------------------------------------------
# unknown fallback


def test_opaque_hex_session_ids_fall_back_to_unknown() -> None:
    template = "session <HEX>"
    samples = [["deadbeef01"], ["cafef00d02"], ["a1b2c3d4e5"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "unknown"
    assert guess["confidence"] == 1.0  # fully confident it is none of the known types


def test_unknown_confidence_drops_when_a_value_could_pass_for_something_else() -> None:
    # "0123456789" is hex text but also happens to be all-digit
    template = "session <HEX>"
    samples = [["deadbeef01"], ["cafef00d02"], ["0123456789"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "unknown"
    assert guess["confidence"] < 1.0


def test_uuids_fall_back_to_unknown() -> None:
    template = "id=<UUID>"
    samples = [["a1b2c3d4-e5f6-7890-abcd-ef1234567890"], ["11111111-2222-3333-4444-555555555555"]]
    (guess,) = infer_field_types(template, samples)
    assert guess["inferred_semantic"] == "unknown"


# --------------------------------------------------------------------------
# confidence reflects consistency, not just majority


def test_confidence_drops_with_noisy_samples() -> None:
    template = "src=<IP>"
    clean = infer_field_types(template, [["10.0.0.1"]] * 10)
    noisy = infer_field_types(template, [["10.0.0.1"]] * 8 + [["garbage"]] * 2)

    assert clean[0]["confidence"] == 1.0
    assert noisy[0]["confidence"] == 0.8
    assert noisy[0]["inferred_semantic"] == "source_ip"  # still the majority rule


def test_example_values_are_capped_at_five_and_deduplicated() -> None:
    template = "src=<IP>"
    samples = [["10.0.0.1"]] * 20 + [["10.0.0.2"]] * 20
    (guess,) = infer_field_types(template, samples)
    assert guess["example_values"] == ["10.0.0.1", "10.0.0.2"]


# --------------------------------------------------------------------------
# edge cases


def test_template_with_no_wildcards_returns_no_guesses() -> None:
    assert infer_field_types("shutdown complete", [[]]) == []


def test_missing_values_at_a_position_do_not_crash_and_yield_unknown() -> None:
    template = "a=<IP> b=<NUM>"
    # some rows are shorter than the wildcard count (ragged real-world data)
    samples = [["10.0.0.1", "5"], ["10.0.0.2"], []]
    guesses = infer_field_types(template, samples)
    assert len(guesses) == 2
    assert guesses[0]["inferred_semantic"] == "source_ip"


def test_completely_empty_samples_yield_unknown_with_zero_confidence() -> None:
    template = "a=<IP>"
    guesses = infer_field_types(template, [])
    assert guesses == [
        {
            "position": 0,
            "mask_type": "IP",
            "inferred_semantic": "unknown",
            "confidence": 0.0,
            "example_values": [],
        }
    ]
