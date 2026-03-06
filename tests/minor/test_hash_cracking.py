"""Tests for Ursa Minor hash cracking."""

import hashlib

import pytest
from ursa_minor.server import crack_hash


class TestCrackHash:

    def test_crack_md5_known_password(self):
        h = hashlib.md5(b"password").hexdigest()
        result = crack_hash(h)
        assert "CRACKED" in result or "cracked" in result.lower()
        assert "password" in result

    def test_crack_sha256_known_password(self):
        h = hashlib.sha256(b"admin").hexdigest()
        result = crack_hash(h)
        assert "cracked" in result.lower()
        assert "admin" in result

    def test_unknown_password_fails(self):
        h = hashlib.md5(b"xK7!mQ2#pZ9@vB4$").hexdigest()
        result = crack_hash(h)
        assert "not cracked" in result.lower() or "no match" in result.lower()

    def test_crack_with_rules_finds_mutation(self):
        # "Password1" should be found via capitalize + suffix rules
        h = hashlib.sha1(b"Password1").hexdigest()
        result = crack_hash(h, use_rules=True)
        assert "cracked" in result.lower()

    def test_invalid_hash_format(self):
        result = crack_hash("xyz123")
        assert "unknown" in result.lower() or "invalid" in result.lower()
