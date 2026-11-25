// SPDX-License-Identifier: MIT

#include "bench_framework.h"

#include <oqs/oqs.h>

#include <math.h>

#if defined(_WIN32)
#include <windows.h>

uint64_t bench_time_ns(void) {
	static LARGE_INTEGER frequency;
	static int initialized = 0;
	LARGE_INTEGER counter;
	if (!initialized) {
		QueryPerformanceFrequency(&frequency);
		initialized = 1;
	}
	QueryPerformanceCounter(&counter);
	return (uint64_t)(((long double)counter.QuadPart * 1000000000.0L) / (long double)frequency.QuadPart);
}
#else
#include <time.h>

uint64_t bench_time_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

void bench_escape(const void *p) {
#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile("" : : "g"(p) : "memory");
#else
	(void)p;
#endif
}

static int bench_compare_double(const void *a, const void *b) {
	double da = *(const double *)a;
	double db = *(const double *)b;
	if (da < db) {
		return -1;
	}
	if (da > db) {
		return 1;
	}
	return 0;
}

void bench_stats_compute(const bench_sample *samples, size_t count, size_t iterations, bench_stats *stats) {
	double *values = NULL;
	double sum = 0.0;
	double sum_sq = 0.0;
	(void)iterations;

	for (size_t i = 0; i < count; i++) {
		sum += samples[i].ops_per_sec;
		sum_sq += samples[i].ops_per_sec * samples[i].ops_per_sec;
	}

	if (count > 0) {
		values = (double *)OQS_MEM_malloc(count * sizeof(double));
		if (values != NULL) {
			for (size_t i = 0; i < count; i++) {
				values[i] = samples[i].ops_per_sec;
			}
			qsort(values, count, sizeof(double), bench_compare_double);
		}
	}

	stats->count = count;
	stats->mean_ops_per_sec = count ? sum / (double)count : 0.0;
	if (count > 0 && values != NULL) {
		if (count % 2 == 1) {
			stats->median_ops_per_sec = values[count / 2];
		} else {
			stats->median_ops_per_sec = (values[count / 2 - 1] + values[count / 2]) / 2.0;
		}
		stats->min_ops_per_sec = values[0];
		stats->max_ops_per_sec = values[count - 1];
	} else {
		stats->median_ops_per_sec = 0.0;
		stats->min_ops_per_sec = 0.0;
		stats->max_ops_per_sec = 0.0;
	}

	if (count > 1) {
		double variance = (sum_sq - sum * sum / (double)count) / (double)(count - 1);
		if (variance < 0.0) {
			variance = 0.0;
		}
		stats->stdev_ops_per_sec = sqrt(variance);
	} else {
		stats->stdev_ops_per_sec = 0.0;
	}
	stats->cv_percent = stats->mean_ops_per_sec > 0.0 ? 100.0 * stats->stdev_ops_per_sec / stats->mean_ops_per_sec : 0.0;
	stats->median_ns_per_op = stats->median_ops_per_sec > 0.0 ? 1e9 / stats->median_ops_per_sec : 0.0;

	if (values != NULL) {
		OQS_MEM_insecure_free(values);
	}
}

double bench_ops_to_mb_s(double ops_per_sec, size_t bytes_per_op) {
	return ops_per_sec * (double)bytes_per_op / 1000000.0;
}
