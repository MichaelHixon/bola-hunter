#!/usr/bin/env python3
"""
Unit tests for bola_hunter's pure logic — the parts that decide WHAT gets
scanned before any network call. Runs with pytest, or standalone:

    python3 tests/test_bola_hunter.py

Covers the natural-key extension: parse_ids must keep integer/range behavior
byte-for-byte while also accepting opaque string keys, and enumerate's list
finder must locate the object array in common collection envelopes.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bola_hunter import (  # noqa: E402
    parse_ids, _find_list, _is_int_token, exclude_owned, enumerate_object_space,
)


# --- fakes for testing enumerate without a network -------------------------

class _FakeResp:
    def __init__(self, status_code, payload, is_json=True):
        self.status_code = status_code
        self._payload = payload
        self._is_json = is_json
        self.text = "" if is_json else payload

    def json(self):
        if not self._is_json:
            raise ValueError("not JSON")
        return self._payload


class _FakeSession:
    """Minimal stand-in: returns a queued response for any .get()."""
    def __init__(self, resp):
        self._resp = resp

    def get(self, path):
        return self._resp


def _raises_systemexit(fn):
    try:
        fn()
    except SystemExit:
        return True
    return False


# --- parse_ids: integer behavior is preserved (now as strings) -------------

def test_single_integer():
    assert parse_ids("48213") == ["48213"]


def test_integer_list_sorted_deduped():
    assert parse_ids("3,1,2,1") == ["1", "2", "3"]


def test_integer_range_expands():
    assert parse_ids("10-13") == ["10", "11", "12", "13"]


def test_mixed_ints_and_range():
    assert parse_ids("100-102,105") == ["100", "101", "102", "105"]


def test_reversed_range_skipped():
    # lo > hi is skipped with a warning, not fatal
    assert parse_ids("13-10,7") == ["7"]


def test_numeric_sorts_numerically_not_lexically():
    # lexical sort would put "10" before "9"; numeric must not
    assert parse_ids("9,10,100") == ["9", "10", "100"]


# --- parse_ids: the new natural-key surface --------------------------------

def test_single_string_key():
    assert parse_ids("secretbook1") == ["secretbook1"]


def test_string_keys_sorted():
    assert parse_ids("charlie,alice,bob") == ["alice", "bob", "charlie"]


def test_uuid_dash_is_literal_not_a_range():
    u = "a1b2c3d4-e5f6"
    assert parse_ids(u) == [u]


def test_mixed_numeric_and_literal_ordering():
    # numerics first (numerically), then literals (lexically)
    assert parse_ids("book2,10,book1,2") == ["2", "10", "book1", "book2"]


def test_empty_and_whitespace():
    assert parse_ids("") == []
    assert parse_ids("  ,  ,") == []


def test_dedupes_literals():
    assert parse_ids("x,x,y") == ["x", "y"]


def test_is_int_token():
    assert _is_int_token("48213")
    assert _is_int_token("-5")
    assert not _is_int_token("secretbook1")
    assert not _is_int_token("a1b2-c3d4")


def test_leading_zero_key_stays_literal():
    # '007' must NOT normalize to '7' — else it wouldn't match enumerate's
    # harvested str form, and exclude_owned would miss the attacker's own object
    assert not _is_int_token("007")
    assert parse_ids("007") == ["007"]
    assert parse_ids("7") == ["7"]


# --- _find_list: locate the object array in a collection response ----------

def test_find_list_explicit_key():
    data = {"Books": [{"book_title": "t1"}], "meta": [1, 2]}
    assert _find_list(data, "Books") == [{"book_title": "t1"}]


def test_find_list_autodetect_first_list():
    data = {"status": "ok", "Books": [{"book_title": "t1"}]}
    assert _find_list(data) == [{"book_title": "t1"}]


def test_find_list_bare_list():
    data = [{"id": 1}, {"id": 2}]
    assert _find_list(data) == data


def test_find_list_missing_key_returns_none():
    assert _find_list({"Books": []}, "Nope") is None


def test_find_list_no_list_returns_none():
    assert _find_list({"a": 1, "b": "two"}) is None


# --- exclude_owned: attacker's own objects are never a BOLA ----------------

def test_exclude_owned_drops_owned_keys():
    assert exclude_owned(["a", "b", "c"], ["b"]) == ["a", "c"]


def test_exclude_owned_preserves_order():
    assert exclude_owned(["3", "1", "2"], ["1"]) == ["3", "2"]


def test_exclude_owned_empty_owned_is_noop():
    assert exclude_owned(["a", "b"], []) == ["a", "b"]


def test_exclude_owned_all_owned_yields_empty():
    assert exclude_owned(["x", "y"], ["x", "y"]) == []


# --- enumerate_object_space: the network-facing recon seam -----------------

def test_enumerate_harvests_keys_autodetect():
    sess = _FakeSession(_FakeResp(200, {"Books": [
        {"book_title": "t1", "user": "a"},
        {"book_title": "t2", "user": "b"},
    ]}))
    assert enumerate_object_space(sess, "/books/v1", "book_title") == ["t1", "t2"]


def test_enumerate_explicit_list_key():
    sess = _FakeSession(_FakeResp(200, {"data": [{"id": 1}, {"id": 2}], "noise": [9]}))
    assert enumerate_object_space(sess, "/x", "id", list_key="data") == ["1", "2"]


def test_enumerate_dedupes_and_coerces_to_str():
    sess = _FakeSession(_FakeResp(200, {"items": [{"id": 5}, {"id": 5}, {"id": 6}]}))
    assert enumerate_object_space(sess, "/x", "id") == ["5", "6"]


def test_enumerate_skips_items_missing_key():
    sess = _FakeSession(_FakeResp(200, {"items": [{"id": "a"}, {"other": "x"}, {"id": "b"}]}))
    assert enumerate_object_space(sess, "/x", "id") == ["a", "b"]


def test_enumerate_non_200_aborts():
    sess = _FakeSession(_FakeResp(403, {}))
    assert _raises_systemexit(lambda: enumerate_object_space(sess, "/x", "id"))


def test_enumerate_non_json_aborts():
    sess = _FakeSession(_FakeResp(200, "<html>", is_json=False))
    assert _raises_systemexit(lambda: enumerate_object_space(sess, "/x", "id"))


def test_enumerate_no_list_aborts():
    sess = _FakeSession(_FakeResp(200, {"a": 1, "b": "two"}))
    assert _raises_systemexit(lambda: enumerate_object_space(sess, "/x", "id"))


def test_enumerate_items_present_but_key_absent_aborts():
    sess = _FakeSession(_FakeResp(200, {"items": [{"other": 1}, {"other": 2}]}))
    assert _raises_systemexit(lambda: enumerate_object_space(sess, "/x", "id"))


if __name__ == "__main__":
    # Standalone runner so the suite works without pytest installed.
    funcs = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for fn in funcs:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {fn.__name__}: {exc}")
    print(f"\n{len(funcs) - failures}/{len(funcs)} passed")
    sys.exit(1 if failures else 0)
