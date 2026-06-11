"""Tests for the structured sanitization consolidation (items 1–7)."""

from __future__ import annotations

import threading

import pytest

from logprivacy import (
    AdapterRegistry,
    Cleaner,
    CleanerPolicy,
    FieldRule,
    LogBlockedError,
    SafeDataResult,
    SafeDataStats,
    to_safe_data,
    to_safe_data_with_result,
)

# ---------------------------------------------------------------------------
# 1. truncate sanitizes before cutting
# ---------------------------------------------------------------------------


class TestTruncateSanitizesFirst:
    def test_secret_after_cutpoint_is_removed(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("data", action="truncate", max_chars=5)
        )
        result = to_safe_data({"data": "hello secret123abc"}, policy=policy)
        assert isinstance(result, dict)
        assert "secret" not in str(result["data"])
        assert "123" not in str(result["data"])

    def test_jwt_secret_removed_before_cut(self) -> None:
        # A JWT-like token that would survive truncation if cut first
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SomeSignatureHere"
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("token", action="truncate", max_chars=20)
        )
        result = to_safe_data({"token": jwt}, policy=policy)
        output = str(result["token"])
        # The raw JWT characters should not appear in the output
        assert "eyJhbGci" not in output

    def test_connection_string_fully_redacted_before_cut(self) -> None:
        conn = "postgresql://user:password123@host:5432/db"
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("db_url", action="truncate", max_chars=25)
        )
        result = to_safe_data({"db_url": conn}, policy=policy)
        output = str(result["db_url"])
        assert "password123" not in output

    def test_text_shorter_than_max_chars_unchanged(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("note", action="truncate", max_chars=100)
        )
        result = to_safe_data({"note": "hello world"}, policy=policy)
        assert result["note"] == "hello world"

    def test_text_exactly_max_chars_no_marker(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("note", action="truncate", max_chars=5)
        )
        result = to_safe_data({"note": "hello"}, policy=policy)
        assert result["note"] == "hello"
        assert "[TRUNCATED]" not in str(result["note"])

    def test_text_longer_than_max_chars_gets_marker(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("note", action="truncate", max_chars=3)
        )
        result = to_safe_data({"note": "hello world"}, policy=policy)
        assert result["note"] == "hel[TRUNCATED]"

    def test_max_chars_zero(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("note", action="truncate", max_chars=0)
        )
        result = to_safe_data({"note": "hello"}, policy=policy)
        assert result["note"] == "[TRUNCATED]"

    def test_bytes_value_sanitized_before_cut(self) -> None:
        data = b"password=secret123 more text here"
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("raw", action="truncate", max_chars=15)
        )
        result = to_safe_data({"raw": data}, policy=policy)
        assert "secret123" not in str(result["raw"])

    def test_non_textual_value_returns_truncated_placeholder(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("num", action="truncate", max_chars=5)
        )
        result = to_safe_data({"num": 42}, policy=policy)
        assert result["num"] == "[TRUNCATED]"

    def test_no_secret_fragment_in_output(self) -> None:
        # Secret is placed after the truncation point; verify it doesn't appear
        secret = "mySuper$ecret!"
        text = f"safe_prefix_{secret}"
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("field", action="truncate", max_chars=10)
        )
        result = to_safe_data({"field": text}, policy=policy)
        assert "Super" not in str(result["field"])
        assert "$ecret" not in str(result["field"])


# ---------------------------------------------------------------------------
# 2. Empty normalized matches are rejected
# ---------------------------------------------------------------------------


class TestEmptyNormalizedMatchRejected:
    @pytest.mark.parametrize("bad_match", ["---", "___", " - _ ", "-"])
    def test_exact_empty_normalized_raises(self, bad_match: str) -> None:
        with pytest.raises(ValueError, match="at least one alphanumeric"):
            FieldRule.exact(bad_match)

    @pytest.mark.parametrize("bad_match", ["---", "___", " - _ "])
    def test_contains_empty_normalized_raises(self, bad_match: str) -> None:
        with pytest.raises(ValueError, match="at least one alphanumeric"):
            FieldRule.contains(bad_match)

    def test_regex_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            FieldRule.regex("")

    def test_regex_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid field rule regex"):
            FieldRule.regex("[")

    def test_regex_broad_is_valid(self) -> None:
        rule = FieldRule.regex(".*")
        assert rule.mode == "regex"

    def test_valid_snake_case_accepted(self) -> None:
        rule = FieldRule.exact("api_key")
        assert rule.match == "api_key"

    def test_valid_camel_case_accepted(self) -> None:
        rule = FieldRule.exact("apiKey")
        assert rule.match == "apiKey"

    def test_valid_unicode_accepted(self) -> None:
        rule = FieldRule.exact("senha1")
        assert rule.match == "senha1"

    def test_existing_rules_still_match(self) -> None:
        rule = FieldRule.exact("password")
        assert rule.matches("password")
        assert rule.matches("Password")
        assert rule.matches("PASSWORD")

    def test_normalized_match_cached_on_instance(self) -> None:
        rule = FieldRule.exact("api-key")
        # Calling matches multiple times should use cached normalized match
        assert rule.matches("api_key")
        assert rule.matches("api-key")
        assert rule.matches("apiKey")


# ---------------------------------------------------------------------------
# 3. Structural rules apply to exception fields
# ---------------------------------------------------------------------------


class TestFieldRulesOnExceptions:
    def test_remove_exception_message(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("message", action="remove")
        )
        exc = ValueError("secret token here")
        result = to_safe_data(exc, policy=policy)
        assert isinstance(result, dict)
        assert result["message"] == "[REMOVED]"

    def test_mask_exception_message(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("message", action="mask"))
        exc = ValueError("some value")
        result = to_safe_data(exc, policy=policy)
        assert isinstance(result, dict)
        assert result["message"] != "some value"
        assert result["message"] != ""

    def test_truncate_exception_message(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("message", action="truncate", max_chars=5)
        )
        exc = ValueError("hello world secret123")
        result = to_safe_data(exc, policy=policy)
        assert isinstance(result, dict)
        assert "secret123" not in str(result["message"])
        assert len(str(result["message"])) <= 5 + len("[TRUNCATED]")

    def test_block_exception_message_raises(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("message", action="block"))
        exc = ValueError("should be blocked")
        with pytest.raises(LogBlockedError):
            to_safe_data(exc, policy=policy)

    def test_mask_exception_type_field(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("type", action="mask"))
        exc = ValueError("some message")
        result = to_safe_data(exc, policy=policy)
        assert isinstance(result, dict)
        # "type" rule matched — value is masked
        assert result["type"] != "ValueError"

    def test_exception_str_raises_handled_safely(self) -> None:
        class BadStr(Exception):
            def __str__(self) -> str:
                raise RuntimeError("boom")

        result = to_safe_data(BadStr())
        assert isinstance(result, dict)
        assert "message" in result

    def test_exception_equivalent_to_mapping(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("message", action="remove")
        )
        exc = ValueError("secret")
        mapping = {"message": "secret"}
        exc_result = to_safe_data(exc, policy=policy)
        map_result = to_safe_data(mapping, policy=policy)
        assert exc_result["message"] == map_result["message"] == "[REMOVED]"

    def test_field_rule_takes_precedence_over_sensitive_keys(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("message", action="remove")
        )
        exc = ValueError("some value")
        result = to_safe_data(exc, policy=policy)
        assert result["message"] == "[REMOVED]"


# ---------------------------------------------------------------------------
# 4 & 5. Adapters fail-closed and reserved types
# ---------------------------------------------------------------------------


class TestAdapterFailClosed:
    def test_reserved_types_rejected(self) -> None:
        registry = AdapterRegistry.default()
        reserved = [
            object,
            str,
            int,
            float,
            bool,
            bytes,
            bytearray,
            memoryview,
            dict,
            list,
            tuple,
            set,
            frozenset,
        ]
        for t in reserved:
            with pytest.raises(ValueError, match="reserved"):
                registry.register(t, lambda v: str(v))

    def test_custom_subclass_of_list_adapter_called_before_structural_fallback(self) -> None:
        # Proves adapter dispatch fires BEFORE the isinstance(value, (list, tuple))
        # structural fallback.  If the structural fallback ran first the result
        # would be [1, 2, 3], not the dict the converter returns.
        class ExternalList(list):  # type: ignore[type-arg]
            pass

        registry = AdapterRegistry.default()
        registry.register(ExternalList, lambda v: {"adapted": True, "items": list(v)})
        result = to_safe_data(ExternalList([1, 2, 3]), adapters=registry)
        assert result == {"adapted": True, "items": [1, 2, 3]}

    def test_converter_raising_returns_unsupported(self) -> None:
        class MyObj:
            pass

        registry = AdapterRegistry.default()
        registry.register(MyObj, lambda v: (_ for _ in ()).throw(RuntimeError("boom")))  # type: ignore[arg-type]

        result = to_safe_data(MyObj(), adapters=registry)
        assert isinstance(result, str)
        assert result.startswith("[UNSUPPORTED:")

    def test_converter_returning_secret_is_sanitized(self) -> None:
        class MyObj:
            pass

        registry = AdapterRegistry.default()
        registry.register(MyObj, lambda v: "password=secret123abc")

        result = to_safe_data(MyObj(), adapters=registry)
        assert "secret123abc" not in str(result)

    def test_converter_returning_self_gives_unsupported(self) -> None:
        class MyObj:
            pass

        obj = MyObj()
        registry = AdapterRegistry.default()
        registry.register(MyObj, lambda v: v)

        result = to_safe_data(obj, adapters=registry)
        assert isinstance(result, str)
        assert result.startswith("[UNSUPPORTED:")

    def test_metaclass_instancecheck_raises_marks_adapter_error(self) -> None:
        # BadABC has __instancecheck__ that raises.  When it is registered and
        # a Concrete() (unrelated, not in registry MRO) is normalized, Phase 2
        # of resolution calls isinstance(Concrete(), BadABC) which triggers
        # BadMeta.__instancecheck__ → raises → resolution_failed=True → the
        # normalizer must mark adapter_error, NOT silently fall through.
        class BadMeta(type):
            def __instancecheck__(cls, instance: object) -> bool:
                raise RuntimeError("boom")

        class BadABC(metaclass=BadMeta):
            pass

        class Concrete:
            pass

        registry = AdapterRegistry.default()
        registry.register(BadABC, lambda v: {"ok": True})

        result = to_safe_data_with_result(Concrete(), adapters=registry)
        assert result.complete is False
        assert "adapter_error" in result.limitations

    def test_converter_produces_cycle_is_handled(self) -> None:
        class MyObj:
            pass

        d: dict[str, object] = {}
        d["self"] = d  # create a cycle

        registry = AdapterRegistry.default()
        registry.register(MyObj, lambda v: d)

        # Should not raise, should handle the cycle
        result = to_safe_data(MyObj(), adapters=registry)
        assert isinstance(result, dict)

    def test_concrete_type_takes_precedence_over_base(self) -> None:
        class Base:
            pass

        class Child(Base):
            pass

        registry = AdapterRegistry.default()
        registry.register(Base, lambda v: "base")
        registry.register(Child, lambda v: "child")

        assert to_safe_data(Child(), adapters=registry) == "child"
        assert to_safe_data(Base(), adapters=registry) == "base"

    def test_adapter_registry_copy_is_independent(self) -> None:
        class MyObj:
            pass

        registry1 = AdapterRegistry.default()
        registry1.register(MyObj, lambda v: "from_r1")

        registry2 = registry1.copy()

        class MyObj2:
            pass

        registry2.register(MyObj2, lambda v: "from_r2")

        # registry1 should NOT have MyObj2
        assert to_safe_data(MyObj2(), adapters=registry1).startswith("[UNSUPPORTED:")  # type: ignore[union-attr]
        # registry2 should have both
        assert to_safe_data(MyObj2(), adapters=registry2) == "from_r2"

    def test_no_original_value_exposed_on_adapter_error(self) -> None:
        class MyObj:
            secret = "password=secret123"

        def bad_converter(v: object) -> object:
            raise RuntimeError("fail")

        registry = AdapterRegistry.default()
        registry.register(MyObj, bad_converter)

        result = str(to_safe_data(MyObj(), adapters=registry))
        assert "secret123" not in result
        assert "password" not in result

    def test_non_type_arg_raises_type_error(self) -> None:
        registry = AdapterRegistry.default()
        with pytest.raises(TypeError, match="must be a type"):
            registry.register("not_a_type", lambda v: v)  # type: ignore[arg-type]

    def test_non_callable_converter_raises_type_error(self) -> None:
        class MyObj:
            pass

        registry = AdapterRegistry.default()
        with pytest.raises(TypeError, match="must be callable"):
            registry.register(MyObj, "not_callable")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 6. Text pipeline is cached per Cleaner instance
# ---------------------------------------------------------------------------


class TestPipelineCachedPerCleaner:
    def test_same_scanner_instance_reused(self) -> None:
        cleaner = Cleaner()
        scanner1 = cleaner._scanner
        scanner2 = cleaner._scanner
        assert scanner1 is scanner2

    def test_same_resolver_instance_reused(self) -> None:
        cleaner = Cleaner()
        assert cleaner._resolver is cleaner._resolver

    def test_same_redactor_instance_reused(self) -> None:
        cleaner = Cleaner()
        assert cleaner._redactor is cleaner._redactor

    def test_different_policies_produce_different_pipelines(self) -> None:
        c1 = Cleaner(policy=CleanerPolicy.default())
        c2 = Cleaner(policy=CleanerPolicy.strict())
        assert c1._scanner is not c2._scanner

    def test_findings_do_not_leak_between_calls(self) -> None:
        cleaner = Cleaner()
        result1 = cleaner.clean_text("my email is user@example.com")
        result2 = cleaner.clean_text("nothing sensitive here")
        assert "user@example.com" not in result1
        assert result2 == "nothing sensitive here"

    def test_results_are_identical_across_calls(self) -> None:
        cleaner = Cleaner()
        text = "token abc123456789xyz"
        assert cleaner.clean_text(text) == cleaner.clean_text(text)

    def test_concurrent_calls_produce_correct_results(self) -> None:
        cleaner = Cleaner()
        results: list[str] = []
        errors: list[Exception] = []

        def worker(n: int) -> None:
            try:
                text = f"user{n}@example.com and safe text {n}"
                r = cleaner.clean_text(text)
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 10
        for r in results:
            assert "@example.com" not in r


# ---------------------------------------------------------------------------
# 7. SafeDataResult / to_safe_data_with_result
# ---------------------------------------------------------------------------


class TestSafeDataResult:
    def test_complete_result_for_clean_input(self) -> None:
        result = to_safe_data_with_result({"name": "Alice", "age": 30})
        assert isinstance(result, SafeDataResult)
        assert result.complete is True
        assert result.limitations == ()

    def test_cleaned_equals_to_safe_data(self) -> None:
        data = {"email": "user@example.com", "name": "Bob"}
        assert to_safe_data_with_result(data).cleaned == to_safe_data(data)

    def test_max_depth_marks_incomplete(self) -> None:
        from dataclasses import replace

        policy = replace(CleanerPolicy.default(), max_depth=0)
        result = to_safe_data_with_result({"outer": {"inner": "x"}}, policy=policy)
        assert result.complete is False
        assert "max_depth" in result.limitations

    def test_max_items_marks_incomplete(self) -> None:
        from dataclasses import replace

        policy = replace(CleanerPolicy.default(), max_items=1)
        result = to_safe_data_with_result({"a": 1, "b": 2, "c": 3}, policy=policy)
        assert result.complete is False
        assert "max_items" in result.limitations

    def test_recursion_marks_incomplete(self) -> None:
        d: dict[str, object] = {}
        d["self"] = d
        result = to_safe_data_with_result(d)
        assert result.complete is False
        assert "recursive_value" in result.limitations

    def test_adapter_error_marks_incomplete(self) -> None:
        class MyObj:
            pass

        def bad_converter(v: object) -> object:
            raise RuntimeError("fail")

        registry = AdapterRegistry.default()
        registry.register(MyObj, bad_converter)

        result = to_safe_data_with_result(MyObj(), adapters=registry)
        assert result.complete is False
        assert "adapter_error" in result.limitations

    def test_unsupported_type_marks_incomplete(self) -> None:
        class CustomThing:
            pass

        result = to_safe_data_with_result(CustomThing())
        assert result.complete is False
        assert "unsupported_type" in result.limitations

    def test_stats_masked_counter(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("password", action="mask"))
        result = to_safe_data_with_result({"password": "secret123"}, policy=policy)
        assert result.stats.masked == 1

    def test_stats_removed_counter(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("password", action="remove")
        )
        result = to_safe_data_with_result({"password": "x", "password2": "y"}, policy=policy)
        # Only "password" matches exact rule
        assert result.stats.removed == 1

    def test_stats_truncated_counter(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("note", action="truncate", max_chars=3)
        )
        result = to_safe_data_with_result({"note": "hello world"}, policy=policy)
        assert result.stats.truncated == 1

    def test_stats_unsupported_counter(self) -> None:
        class CustomThing:
            pass

        result = to_safe_data_with_result({"x": CustomThing()})
        assert result.stats.unsupported >= 1

    def test_stats_adapter_errors_counter(self) -> None:
        class MyObj:
            pass

        registry = AdapterRegistry.default()
        registry.register(MyObj, lambda v: (_ for _ in ()).throw(RuntimeError()))  # type: ignore[arg-type]

        result = to_safe_data_with_result(MyObj(), adapters=registry)
        assert result.stats.adapter_errors == 1

    def test_stats_field_rule_matches_counter(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("a", action="mask"),
            FieldRule.exact("b", action="remove"),
        )
        result = to_safe_data_with_result({"a": "x", "b": "y", "c": "z"}, policy=policy)
        assert result.stats.field_rule_matches == 2

    def test_block_still_raises_logblockederror(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("raw", action="block"))
        with pytest.raises(LogBlockedError):
            to_safe_data_with_result({"raw": "data"}, policy=policy)

    def test_result_is_immutable(self) -> None:
        result = to_safe_data_with_result({"x": 1})
        with pytest.raises((AttributeError, TypeError)):
            result.complete = False  # type: ignore[misc]

    def test_stats_is_immutable(self) -> None:
        result = to_safe_data_with_result({"x": 1})
        with pytest.raises((AttributeError, TypeError)):
            result.stats.masked = 99  # type: ignore[misc]

    def test_result_does_not_retain_original(self) -> None:
        original = {"password": "secret123", "user": "alice"}
        result = to_safe_data_with_result(original)
        # No slot or attribute on SafeDataResult should hold the original
        for attr in ("cleaned", "complete", "limitations", "stats"):
            v = getattr(result, attr)
            assert v is not original

    def test_counters_are_independent_between_calls(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("k", action="mask"))
        r1 = to_safe_data_with_result({"k": "v"}, policy=policy)
        r2 = to_safe_data_with_result({"k": "v", "k2": "v2"}, policy=policy)
        assert r1.stats.masked == 1
        assert r2.stats.masked == 1  # only one field matches the rule

    def test_exception_field_rule_in_result_stats(self) -> None:
        policy = CleanerPolicy.default().add_field_rules(
            FieldRule.exact("message", action="remove")
        )
        result = to_safe_data_with_result(ValueError("secret"), policy=policy)
        assert result.stats.removed == 1
        assert result.stats.field_rule_matches == 1


# ---------------------------------------------------------------------------
# Version alignment (item 9)
# ---------------------------------------------------------------------------


class TestVersionAlignment:
    def test_package_version_matches_init(self) -> None:
        import importlib.metadata

        import logprivacy

        try:
            pkg_version = importlib.metadata.version("logprivacy")
            assert pkg_version == logprivacy.__version__
        except importlib.metadata.PackageNotFoundError:
            # Not installed as a package in this environment — skip metadata check
            pass

    def test_version_present_and_non_empty(self) -> None:
        import logprivacy

        assert logprivacy.__version__
        assert "." in logprivacy.__version__


# ---------------------------------------------------------------------------
# Public API imports (item 8)
# ---------------------------------------------------------------------------


class TestPublicApiImports:
    def test_all_public_names_importable(self) -> None:
        import logprivacy

        expected = [
            "AdapterRegistry",
            "AuditReport",
            "Cleaner",
            "CleanerPolicy",
            "CustomRegexRule",
            "EmailRule",
            "FieldAction",
            "FieldRule",
            "Finding",
            "HashMaskingStrategy",
            "JSONScalar",
            "JSONValue",
            "LogBlockedError",
            "LogPrivacyAssertionError",
            "LogPrivacyError",
            "LogPrivacyFilter",
            "LogPrivacyFormatter",
            "PartialMaskingStrategy",
            "PlaceholderMaskingStrategy",
            "RedactionResult",
            "RuleValidationError",
            "SafeDataResult",
            "SafeDataStats",
            "SecretRule",
            "TokenRule",
            "UrlRule",
            "assert_clean",
            "audit",
            "clean",
            "clean_file",
            "clean_text",
            "clean_url",
            "clean_with_result",
            "explain",
            "get_safe_logger",
            "safe_print",
            "safe_json_dump",
            "safe_json_dumps",
            "scan_file",
            "to_safe_data",
            "to_safe_data_with_result",
        ]
        for name in expected:
            assert hasattr(logprivacy, name), f"Missing from public API: {name}"

    def test_safe_data_result_is_frozen_dataclass(self) -> None:
        result = SafeDataResult(
            cleaned={"x": 1},
            complete=True,
            limitations=(),
            stats=SafeDataStats(),
        )
        assert result.cleaned == {"x": 1}
        assert result.complete is True
        assert result.limitations == ()

    def test_safe_data_stats_defaults_to_zero(self) -> None:
        stats = SafeDataStats()
        assert stats.masked == 0
        assert stats.removed == 0
        assert stats.truncated == 0
        assert stats.unsupported == 0
        assert stats.adapter_errors == 0
        assert stats.field_rule_matches == 0
