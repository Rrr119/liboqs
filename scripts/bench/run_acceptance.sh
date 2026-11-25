#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# One-command reproducibility acceptance + selection table generation for the
# five default PQC algorithms. Extra arguments are forwarded to
# scripts/bench/run_benchmark.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

PYTHON="${PYTHON:-python3}"

# Fast, proven profile: short adaptive batches keep the comparison window small
# on shared/noisy hosts, and retries absorb transient load spikes.
exec "${PYTHON}" scripts/bench/run_benchmark.py \
	--cpu auto \
	--batch-ms 50 \
	--warmup 8 \
	--repeats 7 \
	--runs 2 \
	--tolerance 0.15 \
	--attempts 10 \
	"$@"
