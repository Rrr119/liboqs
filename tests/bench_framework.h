// SPDX-License-Identifier: MIT

/**
 * \file bench_framework.h
 * \brief Timing and statistics primitives for the unified liboqs benchmark.
 *
 * The framework measures fixed-iteration batches: an untimed warm-up is
 * followed by @c repeats timed batches of @c iterations operations.  Every
 * batch throughput sample is retained and statistics (median/mean/stdev/...)
 * are computed over the samples.  Comparing medians of identical invocations
 * is the basis of the same-machine/same-parameters reproducibility check.
 */

#ifndef OQS_BENCH_FRAMEWORK_H
#define OQS_BENCH_FRAMEWORK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Monotonic timestamp in nanoseconds.
 *
 * The clock is monotonic wherever the platform provides one, so wall-clock
 * adjustments cannot distort measurements.
 */
uint64_t bench_time_ns(void);

/**
 * \brief Prevent the compiler from treating the memory at @p p as dead.
 *
 * Used after timing loops so operation outputs cannot be optimized away.
 */
void bench_escape(const void *p);

/** One timed batch. */
typedef struct bench_sample {
	uint64_t elapsed_ns;
	double ops_per_sec;
} bench_sample;

/** Summary statistics over repeated batch samples. */
typedef struct bench_stats {
	size_t count; /**< Number of batches. */
	double median_ops_per_sec;
	double mean_ops_per_sec;
	double stdev_ops_per_sec; /**< Sample standard deviation. */
	double min_ops_per_sec;
	double max_ops_per_sec;
	double cv_percent; /**< Coefficient of variation (stdev / mean * 100). */
	double median_ns_per_op;
} bench_stats;

/**
 * \brief Compute summary statistics for @p samples.
 *
 * @param samples    Timed batches.
 * @param count      Number of samples.
 * @param iterations Operations per batch (used for ns/op).
 * @param stats      Output structure.
 */
void bench_stats_compute(const bench_sample *samples, size_t count, size_t iterations, bench_stats *stats);

/**
 * \brief Convert an operations/second rate to decimal MB/s.
 * @param ops_per_sec Operation throughput.
 * @param bytes_per_op Bytes attributed to one operation (documented per op).
 * @return MB/s where 1 MB = 1,000,000 bytes.
 */
double bench_ops_to_mb_s(double ops_per_sec, size_t bytes_per_op);

#ifdef __cplusplus
}
#endif

#endif /* OQS_BENCH_FRAMEWORK_H */
