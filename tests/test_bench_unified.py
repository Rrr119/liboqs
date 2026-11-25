# SPDX-License-Identifier: MIT

"""Smoke/schema/reproducibility tests for the unified bench_unified tool.

The heavy two-run acceptance with the five migration algorithms lives in
``scripts/bench/run_benchmark.py``; these tests only pin the JSON schema,
exact size reporting and same-parameter size reproducibility.
"""

import json

import helpers
import pytest


def _run_json(tmp_path, algorithms, iterations=40, repeats=3):
    output = tmp_path / "bench_unified.json"
    command = [
        helpers.path_to_executable("bench_unified"),
        "--format", "json",
        "--output", str(output),
        "--iterations", str(iterations),
        "--warmup", "2",
        "--repeats", str(repeats),
        "--algorithms", ",".join(algorithms),
    ]
    helpers.run_subprocess(command)
    with open(output, encoding="utf-8") as handle:
        return json.load(handle)


def _assert_schema(report, algorithm, kind, operation_names):
    assert report["schema_version"] == 1
    result = next(item for item in report["results"] if item["algorithm"] == algorithm)
    assert result["kind"] == kind
    sizes = result["sizes"]
    assert sizes["public_key_bytes"] > 0
    assert sizes["secret_key_bytes"] > 0
    assert sizes["object_max_bytes"] > 0
    operations = result["operations"]
    assert list(operations.keys()) == operation_names
    for name in operation_names:
        op = operations[name]
        assert op["iterations"] > 0
        assert op["median_ops_per_sec"] > 0.0
        assert op["median_us_per_op"] > 0.0
        assert len(op["samples_ops_per_sec"]) >= 1
    return result


@helpers.filtered_test
def test_bench_unified_list():
    output = helpers.run_subprocess([helpers.path_to_executable("bench_unified"), "--list"])
    assert "ML-KEM-768" in output
    assert "ML-DSA-65" in output


@helpers.filtered_test
def test_bench_unified_kem_sizes_and_schema(tmp_path):
    if not helpers.is_kem_enabled_by_name("ML-KEM-768"):
        pytest.skip("ML-KEM-768 not enabled")
    report = _run_json(tmp_path, ["ML-KEM-768"])
    result = _assert_schema(report, "ML-KEM-768", "kem", ["keypair", "encaps", "decaps"])
    assert result["nist_level"] == 3
    assert result["ind_cca"] is True
    assert result["sizes"]["public_key_bytes"] == 1184
    assert result["sizes"]["object_max_bytes"] == 1088
    assert result["sizes"]["shared_secret_bytes"] == 32


@helpers.filtered_test
def test_bench_unified_sig_sizes_and_schema(tmp_path):
    if not helpers.is_sig_enabled_by_name("ML-DSA-65"):
        pytest.skip("ML-DSA-65 not enabled")
    report = _run_json(tmp_path, ["ML-DSA-65"])
    result = _assert_schema(report, "ML-DSA-65", "sig", ["keypair", "sign", "verify"])
    assert result["nist_level"] == 3
    assert result["ind_cca"] is None
    assert result["sizes"]["public_key_bytes"] == 1952
    assert result["sizes"]["object_actual_bytes"] > 0


@helpers.filtered_test
def test_bench_unified_csv_header(tmp_path):
    if not helpers.is_kem_enabled_by_name("ML-KEM-768"):
        pytest.skip("ML-KEM-768 not enabled")
    executable = helpers.path_to_executable("bench_unified")
    csv_output = tmp_path / "bench.csv"
    helpers.run_subprocess(
        [executable, "ML-KEM-768", "-n", "5", "-w", "1", "-r", "1", "-f", "csv", "-o", str(csv_output)]
    )
    first_line = csv_output.read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith("schema_version,algorithm,kind,nist_level")
    assert "median_ops_per_sec" in first_line


@helpers.filtered_test
def test_bench_unified_repeated_runs_same_sizes(tmp_path):
    if not helpers.is_kem_enabled_by_name("ML-KEM-768"):
        pytest.skip("ML-KEM-768 not enabled")
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    run_a = _run_json(dir_a, ["ML-KEM-768"], iterations=80, repeats=3)
    run_b = _run_json(dir_b, ["ML-KEM-768"], iterations=80, repeats=3)
    res_a = run_a["results"][0]
    res_b = run_b["results"][0]
    assert res_a["sizes"] == res_b["sizes"]
    for operation in ("keypair", "encaps", "decaps"):
        rate_a = res_a["operations"][operation]["median_ops_per_sec"]
        rate_b = res_b["operations"][operation]["median_ops_per_sec"]
        # Generous bound on purpose: exact timing stability is checked by
        # scripts/bench/run_benchmark.py on a pinned, idle machine.
        assert 0.5 < rate_a / rate_b < 2.0
