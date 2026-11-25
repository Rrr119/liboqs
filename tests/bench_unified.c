// SPDX-License-Identifier: MIT

/**
 * \file bench_unified.c
 * \brief Unified benchmark and size report for liboqs KEM and SIG algorithms.
 *
 * One binary and one output schema cover both public API families
 * (#OQS_KEM and #OQS_SIG).  For every algorithm it reports the key and
 * object sizes exposed in the public structs together with throughput
 * (operations/s, microseconds/op and MB/s) of each operation.
 *
 * Measurements use fixed-iteration batches with warm-up and repeated batches
 * (see bench_framework.h), which makes identical command lines reproducible
 * on the same machine.  The tool only uses the public <oqs/oqs.h> API and is
 * fully additive: the existing speed_kem and speed_sig tools are unchanged.
 */

#include <oqs/oqs.h>

#include "bench_framework.h"
#include "system_info.c"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** Algorithms benchmarked when no algorithm is requested explicitly. */
static const char *k_default_algorithms[] = {
	OQS_KEM_alg_ml_kem_768,
	OQS_KEM_alg_ml_kem_1024,
	OQS_SIG_alg_ml_dsa_65,
	OQS_SIG_alg_falcon_512,
	OQS_SIG_alg_slh_dsa_pure_sha2_128f,
};

#define DEFAULT_ALGORITHM_COUNT (sizeof(k_default_algorithms) / sizeof(k_default_algorithms[0]))
#define BENCH_OP_COUNT 3
#define BENCH_MESSAGE_BYTES 64

typedef enum bench_kind {
	BENCH_KIND_KEM = 0,
	BENCH_KIND_SIG = 1
} bench_kind;

typedef struct bench_config {
	size_t iterations;
	size_t warmup;
	size_t repeats;
	size_t batch_ms; /**< Adaptive target batch duration when iterations == 0. */
	const char *format; /**< "text", "table", "csv" or "json". */
	const char *output_path;
	bool run_all;
	bool list_only;
	bool help_only;
	const char **algorithms;
	size_t algorithms_len;
	size_t algorithms_cap;
} bench_config;

typedef struct bench_result {
	const char *name;
	bench_kind kind;
	int nist_level;
	int ind_cca; /**< -1 for signatures, 0/1 for KEMs. */
	size_t pk_bytes;
	size_t sk_bytes;
	size_t object_max_bytes;
	size_t object_actual_bytes;
	size_t shared_secret_bytes;
	size_t message_bytes;
	const char *op_name[BENCH_OP_COUNT];
	size_t payload_bytes[BENCH_OP_COUNT];
	size_t op_iterations[BENCH_OP_COUNT];
	bench_sample *samples[BENCH_OP_COUNT];
	bench_stats stats[BENCH_OP_COUNT];
} bench_result;

#define BENCH_CALIBRATE_MAX_ITERATIONS ((size_t)1 << 20)

/* Picks a stable batch size: explicit --iterations wins, otherwise grow the
 * iteration count exponentially until one batch lasts --batch-ms. */
#define BENCH_DETERMINE_ITERATIONS(EXPR, CFG, OUT_N)                                                         \
	do {                                                                                                     \
		if ((CFG)->iterations > 0) {                                                                         \
			(OUT_N) = (CFG)->iterations;                                                                     \
		} else {                                                                                             \
			size_t bench_n = 1;                                                                              \
			const uint64_t bench_target_ns = (uint64_t)(CFG)->batch_ms * 1000000ULL;                         \
			while (true) {                                                                                   \
				uint64_t bench_ct0 = bench_time_ns();                                                        \
				for (size_t bench_ci = 0; bench_ci < bench_n; bench_ci++) {                                  \
					if ((EXPR) != OQS_SUCCESS) {                                                              \
						bench_die_status(#EXPR, __FILE__, __LINE__);                                         \
					}                                                                                        \
				}                                                                                            \
				uint64_t bench_celapsed = bench_time_ns() - bench_ct0;                                       \
				if (bench_celapsed >= bench_target_ns || bench_n >= BENCH_CALIBRATE_MAX_ITERATIONS) {        \
					break;                                                                                    \
				}                                                                                            \
				if (bench_n > BENCH_CALIBRATE_MAX_ITERATIONS / 2) {                                           \
					bench_n = BENCH_CALIBRATE_MAX_ITERATIONS;                                                 \
				} else {                                                                                     \
					bench_n *= 2;                                                                             \
				}                                                                                            \
			}                                                                                                \
			(OUT_N) = bench_n;                                                                               \
		}                                                                                                    \
	} while (0)

static void *bench_xalloc(size_t size) {
	void *ptr = OQS_MEM_malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "bench_unified: out of memory (%zu bytes)\n", size);
		exit(EXIT_FAILURE);
	}
	return ptr;
}

static void bench_die_status(const char *expression, const char *file, int line) {
	fprintf(stderr, "bench_unified: operation failed: %s (%s:%d)\n", expression, file, line);
	exit(EXIT_FAILURE);
}

/* Runs warm-up batches followed by cfg->repeats timed fixed-size batches. */
#define BENCH_RUN_SERIES(EXPR, ITERATIONS, CFG, OUT_SAMPLES, OUT_STATS)                                          \
	do {                                                                                                         \
		for (size_t bench_w = 0; bench_w < (CFG)->warmup; bench_w++) {                                           \
			if ((EXPR) != OQS_SUCCESS) {                                                                         \
				bench_die_status(#EXPR, __FILE__, __LINE__);                                                     \
			}                                                                                                    \
		}                                                                                                        \
		(OUT_SAMPLES) = (bench_sample *)bench_xalloc((CFG)->repeats * sizeof(bench_sample));                     \
		for (size_t bench_r = 0; bench_r < (CFG)->repeats; bench_r++) {                                          \
			uint64_t bench_t0 = bench_time_ns();                                                                 \
			for (size_t bench_i = 0; bench_i < (ITERATIONS); bench_i++) {                                       \
				if ((EXPR) != OQS_SUCCESS) {                                                                     \
					bench_die_status(#EXPR, __FILE__, __LINE__);                                                 \
				}                                                                                                \
			}                                                                                                    \
			uint64_t bench_t1 = bench_time_ns();                                                                 \
			uint64_t bench_elapsed = bench_t1 - bench_t0;                                                        \
			(OUT_SAMPLES)[bench_r].elapsed_ns = bench_elapsed;                                                   \
			(OUT_SAMPLES)[bench_r].ops_per_sec = (double)(ITERATIONS) * 1000000000.0 / (double)bench_elapsed;   \
		}                                                                                                        \
		bench_stats_compute((OUT_SAMPLES), (CFG)->repeats, (ITERATIONS), (OUT_STATS));                           \
	} while (0)

static bench_result *benchmark_kem(const char *name, const bench_config *cfg) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return NULL;
	}

	bench_result *res = (bench_result *)bench_xalloc(sizeof(bench_result));
	memset(res, 0, sizeof(*res));
	res->name = name;
	res->kind = BENCH_KIND_KEM;
	res->nist_level = kem->claimed_nist_level;
	res->ind_cca = kem->ind_cca ? 1 : 0;
	res->pk_bytes = kem->length_public_key;
	res->sk_bytes = kem->length_secret_key;
	res->object_max_bytes = kem->length_ciphertext;
	res->object_actual_bytes = kem->length_ciphertext;
	res->shared_secret_bytes = kem->length_shared_secret;
	res->message_bytes = 0;
	res->op_name[0] = "keypair";
	res->op_name[1] = "encaps";
	res->op_name[2] = "decaps";
	res->payload_bytes[0] = kem->length_public_key + kem->length_secret_key;
	res->payload_bytes[1] = kem->length_ciphertext;
	res->payload_bytes[2] = kem->length_ciphertext;

	uint8_t *public_key = (uint8_t *)bench_xalloc(kem->length_public_key);
	uint8_t *secret_key = (uint8_t *)bench_xalloc(kem->length_secret_key);
	uint8_t *ciphertext = (uint8_t *)bench_xalloc(kem->length_ciphertext);
	uint8_t *shared_secret_e = (uint8_t *)bench_xalloc(kem->length_shared_secret);
	uint8_t *shared_secret_d = (uint8_t *)bench_xalloc(kem->length_shared_secret);

	if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS ||
	    OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key) != OQS_SUCCESS ||
	    OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key) != OQS_SUCCESS) {
		bench_die_status("KEM roundtrip", __FILE__, __LINE__);
	}
	if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) != 0) {
		fprintf(stderr, "bench_unified: %s: KEM encaps/decaps shared secrets differ\n", name);
		exit(EXIT_FAILURE);
	}

	BENCH_DETERMINE_ITERATIONS(OQS_KEM_keypair(kem, public_key, secret_key), cfg, res->op_iterations[0]);
	BENCH_RUN_SERIES(OQS_KEM_keypair(kem, public_key, secret_key), res->op_iterations[0], cfg, res->samples[0], &res->stats[0]);
	bench_escape(public_key);
	bench_escape(secret_key);

	BENCH_DETERMINE_ITERATIONS(OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key), cfg, res->op_iterations[1]);
	BENCH_RUN_SERIES(OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key), res->op_iterations[1], cfg, res->samples[1], &res->stats[1]);
	bench_escape(ciphertext);
	bench_escape(shared_secret_e);

	BENCH_DETERMINE_ITERATIONS(OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key), cfg, res->op_iterations[2]);
	BENCH_RUN_SERIES(OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key), res->op_iterations[2], cfg, res->samples[2], &res->stats[2]);
	bench_escape(shared_secret_d);

	OQS_MEM_secure_free(secret_key, kem->length_secret_key);
	OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
	OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
	return res;
}

static size_t bench_sig_message_length(const char *name) {
#if defined(OQS_ENABLE_SIG_ml_dsa_44_extmu)
	if (strcmp(name, OQS_SIG_alg_ml_dsa_44_extmu) == 0) {
		return OQS_SIG_ml_dsa_44_extmu_length_mu;
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65_extmu)
	if (strcmp(name, OQS_SIG_alg_ml_dsa_65_extmu) == 0) {
		return OQS_SIG_ml_dsa_65_extmu_length_mu;
	}
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_87_extmu)
	if (strcmp(name, OQS_SIG_alg_ml_dsa_87_extmu) == 0) {
		return OQS_SIG_ml_dsa_87_extmu_length_mu;
	}
#endif
	return BENCH_MESSAGE_BYTES;
}

static bench_result *benchmark_sig(const char *name, const bench_config *cfg) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return NULL;
	}

	bench_result *res = (bench_result *)bench_xalloc(sizeof(bench_result));
	memset(res, 0, sizeof(*res));
	res->name = name;
	res->kind = BENCH_KIND_SIG;
	res->nist_level = sig->claimed_nist_level;
	res->ind_cca = -1;
	res->pk_bytes = sig->length_public_key;
	res->sk_bytes = sig->length_secret_key;
	res->object_max_bytes = sig->length_signature;
	res->object_actual_bytes = sig->length_signature;
	res->shared_secret_bytes = 0;
	res->message_bytes = bench_sig_message_length(name);
	res->op_name[0] = "keypair";
	res->op_name[1] = "sign";
	res->op_name[2] = "verify";
	res->payload_bytes[0] = sig->length_public_key + sig->length_secret_key;

	uint8_t *public_key = (uint8_t *)bench_xalloc(sig->length_public_key);
	uint8_t *secret_key = (uint8_t *)bench_xalloc(sig->length_secret_key);
	uint8_t *message = (uint8_t *)bench_xalloc(res->message_bytes);
	uint8_t *signature = (uint8_t *)bench_xalloc(sig->length_signature);
	size_t signature_len = sig->length_signature;

	OQS_randombytes(message, res->message_bytes);

	if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS ||
	    OQS_SIG_sign(sig, signature, &signature_len, message, res->message_bytes, secret_key) != OQS_SUCCESS ||
	    OQS_SIG_verify(sig, message, res->message_bytes, signature, signature_len, public_key) != OQS_SUCCESS) {
		bench_die_status("SIG sign/verify roundtrip", __FILE__, __LINE__);
	}

	BENCH_DETERMINE_ITERATIONS(OQS_SIG_keypair(sig, public_key, secret_key), cfg, res->op_iterations[0]);
	BENCH_RUN_SERIES(OQS_SIG_keypair(sig, public_key, secret_key), res->op_iterations[0], cfg, res->samples[0], &res->stats[0]);
	bench_escape(public_key);
	bench_escape(secret_key);

	BENCH_DETERMINE_ITERATIONS(OQS_SIG_sign(sig, signature, &signature_len, message, res->message_bytes, secret_key), cfg, res->op_iterations[1]);
	BENCH_RUN_SERIES(OQS_SIG_sign(sig, signature, &signature_len, message, res->message_bytes, secret_key), res->op_iterations[1], cfg, res->samples[1], &res->stats[1]);
	bench_escape(signature);

	/* Capture the real (possibly variable) signature size. */
	signature_len = sig->length_signature;
	if (OQS_SIG_sign(sig, signature, &signature_len, message, res->message_bytes, secret_key) != OQS_SUCCESS) {
		bench_die_status("OQS_SIG_sign", __FILE__, __LINE__);
	}
	res->object_actual_bytes = signature_len;
	res->payload_bytes[1] = signature_len;
	res->payload_bytes[2] = signature_len;

	BENCH_DETERMINE_ITERATIONS(OQS_SIG_verify(sig, message, res->message_bytes, signature, signature_len, public_key), cfg, res->op_iterations[2]);
	BENCH_RUN_SERIES(OQS_SIG_verify(sig, message, res->message_bytes, signature, signature_len, public_key), res->op_iterations[2], cfg, res->samples[2], &res->stats[2]);
	bench_escape(message);
	bench_escape(signature);

	OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
	return res;
}

/* ------------------------------------------------------------------ */
/* Output rendering                                                    */
/* ------------------------------------------------------------------ */

static const char *bench_kind_name(bench_kind kind) {
	return kind == BENCH_KIND_KEM ? "kem" : "sig";
}

static void print_json_operation(FILE *out, const bench_result *res, int op_index, bool last_op) {
	const bench_stats *st = &res->stats[op_index];
	const bench_sample *samples = res->samples[op_index];
	fprintf(out, "\t\t\t\"%s\": {\n", res->op_name[op_index]);
	fprintf(out, "\t\t\t\t\"iterations\": %zu,\n", res->op_iterations[op_index]);
	fprintf(out, "\t\t\t\t\"payload_bytes_per_op\": %zu,\n", res->payload_bytes[op_index]);
	fprintf(out, "\t\t\t\t\"median_ops_per_sec\": %.6f,\n", st->median_ops_per_sec);
	fprintf(out, "\t\t\t\t\"median_us_per_op\": %.6f,\n", st->median_ns_per_op / 1000.0);
	fprintf(out, "\t\t\t\t\"median_mb_per_s\": %.6f,\n", bench_ops_to_mb_s(st->median_ops_per_sec, res->payload_bytes[op_index]));
	fprintf(out, "\t\t\t\t\"mean_ops_per_sec\": %.6f,\n", st->mean_ops_per_sec);
	fprintf(out, "\t\t\t\t\"stdev_ops_per_sec\": %.6f,\n", st->stdev_ops_per_sec);
	fprintf(out, "\t\t\t\t\"cv_percent\": %.6f,\n", st->cv_percent);
	fprintf(out, "\t\t\t\t\"min_ops_per_sec\": %.6f,\n", st->min_ops_per_sec);
	fprintf(out, "\t\t\t\t\"max_ops_per_sec\": %.6f,\n", st->max_ops_per_sec);
	fprintf(out, "\t\t\t\t\"samples_ops_per_sec\": [");
	for (size_t i = 0; i < st->count; i++) {
		fprintf(out, "%s%.6f", i == 0 ? "" : ", ", samples[i].ops_per_sec);
	}
	fprintf(out, "],\n");
	fprintf(out, "\t\t\t\t\"samples_elapsed_ns\": [");
	for (size_t i = 0; i < st->count; i++) {
		fprintf(out, "%s%" PRIu64, i == 0 ? "" : ", ", samples[i].elapsed_ns);
	}
	fprintf(out, "]\n");
	fprintf(out, "\t\t\t}%s\n", last_op ? "" : ",");
}

static void print_json(FILE *out, const bench_config *cfg, bench_result **results, size_t results_len) {
	time_t now = time(NULL);
	struct tm utc_tm;
	char timestamp[40];
#if defined(_WIN32)
	gmtime_s(&utc_tm, &now);
#else
	gmtime_r(&now, &utc_tm);
#endif
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc_tm);

	fprintf(out, "{\n");
	fprintf(out, "\t\"schema_version\": 1,\n");
	fprintf(out, "\t\"tool\": \"bench_unified\",\n");
	fprintf(out, "\t\"generated_utc\": \"%s\",\n", timestamp);
	fprintf(out, "\t\"timer\": \"bench_time_ns: monotonic nanosecond clock (CLOCK_MONOTONIC/QPC)\",\n");
	fprintf(out, "\t\"parameters\": {\n");
	fprintf(out, "\t\t\"iterations\": %zu,\n", cfg->iterations);
	fprintf(out, "\t\t\"iteration_mode\": \"%s\",\n", cfg->iterations > 0 ? "fixed" : "adaptive");
	fprintf(out, "\t\t\"batch_target_ms\": %zu,\n", cfg->batch_ms);
	fprintf(out, "\t\t\"warmup\": %zu,\n", cfg->warmup);
	fprintf(out, "\t\t\"repeats\": %zu,\n", cfg->repeats);
	fprintf(out, "\t\t\"message_bytes\": %d\n", BENCH_MESSAGE_BYTES);
	fprintf(out, "\t},\n");
	fprintf(out, "\t\"results\": [\n");
	for (size_t i = 0; i < results_len; i++) {
		bench_result *res = results[i];
		fprintf(out, "\t\t{\n");
		fprintf(out, "\t\t\t\"algorithm\": \"%s\",\n", res->name);
		fprintf(out, "\t\t\t\"kind\": \"%s\",\n", bench_kind_name(res->kind));
		fprintf(out, "\t\t\t\"nist_level\": %d,\n", res->nist_level);
		if (res->ind_cca < 0) {
			fprintf(out, "\t\t\t\"ind_cca\": null,\n");
		} else {
			fprintf(out, "\t\t\t\"ind_cca\": %s,\n", res->ind_cca ? "true" : "false");
		}
		fprintf(out, "\t\t\t\"sizes\": {\n");
		fprintf(out, "\t\t\t\t\"public_key_bytes\": %zu,\n", res->pk_bytes);
		fprintf(out, "\t\t\t\t\"secret_key_bytes\": %zu,\n", res->sk_bytes);
		fprintf(out, "\t\t\t\t\"object_max_bytes\": %zu,\n", res->object_max_bytes);
		fprintf(out, "\t\t\t\t\"object_actual_bytes\": %zu,\n", res->object_actual_bytes);
		fprintf(out, "\t\t\t\t\"shared_secret_bytes\": %zu\n", res->shared_secret_bytes);
		fprintf(out, "\t\t\t},\n");
		fprintf(out, "\t\t\t\"operations\": {\n");
		print_json_operation(out, res, 0, false);
		print_json_operation(out, res, 1, false);
		print_json_operation(out, res, 2, true);
		fprintf(out, "\t\t\t}\n");
		fprintf(out, "\t\t}%s\n", i + 1 == results_len ? "" : ",");
	}
	fprintf(out, "\t]\n");
	fprintf(out, "}\n");
}

static void print_csv(FILE *out, const bench_config *cfg, bench_result **results, size_t results_len) {
	fprintf(out,
	        "schema_version,algorithm,kind,nist_level,ind_cca,public_key_bytes,secret_key_bytes,"
	        "object_max_bytes,object_actual_bytes,shared_secret_bytes,message_bytes,operation,operation_order,"
	        "iterations,warmup,repeats,payload_bytes_per_op,median_ops_per_sec,median_us_per_op,median_mb_per_s,"
	        "mean_ops_per_sec,stdev_ops_per_sec,cv_percent,min_ops_per_sec,max_ops_per_sec\n");
	for (size_t i = 0; i < results_len; i++) {
		bench_result *res = results[i];
		for (int op = 0; op < BENCH_OP_COUNT; op++) {
			const bench_stats *st = &res->stats[op];
			fprintf(out, "1,%s,%s,%d,", res->name, bench_kind_name(res->kind), res->nist_level);
			if (res->ind_cca < 0) {
				fprintf(out, "na,");
			} else {
				fprintf(out, "%s,", res->ind_cca ? "true" : "false");
			}
			fprintf(out, "%zu,%zu,%zu,%zu,%zu,%zu,%s,%d,%zu,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
			        res->pk_bytes, res->sk_bytes, res->object_max_bytes, res->object_actual_bytes,
			        res->shared_secret_bytes, res->message_bytes, res->op_name[op], op,
			        res->op_iterations[op], cfg->warmup, cfg->repeats, res->payload_bytes[op],
			        st->median_ops_per_sec, st->median_ns_per_op / 1000.0,
			        bench_ops_to_mb_s(st->median_ops_per_sec, res->payload_bytes[op]),
			        st->mean_ops_per_sec, st->stdev_ops_per_sec, st->cv_percent,
			        st->min_ops_per_sec, st->max_ops_per_sec);
		}
	}
}

static void print_text_blocks(FILE *out, bench_result **results, size_t results_len) {
	for (size_t i = 0; i < results_len; i++) {
		bench_result *res = results[i];
		fprintf(out, "[%zu/%zu] %s  (%s, NIST level %d", i + 1, results_len, res->name,
		        res->kind == BENCH_KIND_KEM ? "KEM" : "signature", res->nist_level);
		if (res->kind == BENCH_KIND_KEM) {
			fprintf(out, ", IND-CCA %s", res->ind_cca ? "yes" : "no");
		}
		fprintf(out, ")\n");
		fprintf(out, "  sizes (bytes): public_key=%zu secret_key=%zu %s_max=%zu %s_actual=%zu",
		        res->pk_bytes, res->sk_bytes, res->kind == BENCH_KIND_KEM ? "ciphertext" : "signature",
		        res->object_max_bytes, res->kind == BENCH_KIND_KEM ? "ciphertext" : "signature",
		        res->object_actual_bytes);
		if (res->kind == BENCH_KIND_KEM) {
			fprintf(out, " shared_secret=%zu", res->shared_secret_bytes);
		} else {
			fprintf(out, " message=%zu", res->message_bytes);
		}
		fprintf(out, "\n");
		fprintf(out, "  %-10s %9s %13s %15s %13s %12s %7s\n", "operation", "iters", "payload_B/op",
		        "ops/s (median)", "us/op (median)", "MB/s (median)", "CV%");
		for (int op = 0; op < BENCH_OP_COUNT; op++) {
			const bench_stats *st = &res->stats[op];
			fprintf(out, "  %-10s %9zu %13zu %15.2f %13.3f %12.2f %6.2f%%\n", res->op_name[op],
			        res->op_iterations[op], res->payload_bytes[op], st->median_ops_per_sec,
			        st->median_ns_per_op / 1000.0,
			        bench_ops_to_mb_s(st->median_ops_per_sec, res->payload_bytes[op]), st->cv_percent);
		}
		fprintf(out, "\n");
	}
}

static void print_wide_table(FILE *out, bench_result **results, size_t results_len) {
	fprintf(out, "%-38s %-4s %3s %5s %8s %8s %9s %13s %15s %15s\n", "algorithm", "kind", "lvl", "CCA",
	        "pk(B)", "sk(B)", "obj(B)", "keygen ops/s", "enc|sign ops/s", "dec|ver ops/s");
	for (size_t i = 0; i < results_len; i++) {
		bench_result *res = results[i];
		char cca[6];
		if (res->ind_cca < 0) {
			snprintf(cca, sizeof(cca), "-");
		} else {
			snprintf(cca, sizeof(cca), "%s", res->ind_cca ? "Y" : "N");
		}
		fprintf(out, "%-38s %-4s %3d %5s %8zu %8zu %9zu %13.1f %15.1f %15.1f\n", res->name,
		        bench_kind_name(res->kind), res->nist_level, cca, res->pk_bytes, res->sk_bytes,
		        res->object_actual_bytes, res->stats[0].median_ops_per_sec,
		        res->stats[1].median_ops_per_sec, res->stats[2].median_ops_per_sec);
	}
}

static void print_usage(FILE *out, const char *program) {
	fprintf(out,
	        "Usage: %s [options] [algorithm ...]\n"
	        "\n"
	        "Unified benchmark for liboqs KEM and signature algorithms. Reports\n"
	        "key/object sizes plus per-operation throughput.\n"
	        "\n"
	        "If no algorithm is given, five migration-relevant algorithms are run:\n"
	        "ML-KEM-768, ML-KEM-1024, ML-DSA-65, Falcon-512, SLH_DSA_PURE_SHA2_128F.\n"
	        "\n"
	        "Options:\n"
	        "  -a, --algorithms <a,b,...>  Comma-separated algorithm list.\n"
	        "      --all                   Benchmark every enabled KEM and signature.\n"
	        "      --list                  List all known algorithms and enabled state.\n"
	        "  -n, --iterations <N>        Fixed iterations per timed batch (default: adaptive).\n"
	        "      --batch-ms <ms>         Adaptive target batch duration (default 200 ms).\n"
	        "  -w, --warmup <N>            Untimed warm-up iterations (default 20).\n"
	        "  -r, --repeats <N>           Timed batches per algorithm/op (default 5).\n"
	        "  -f, --format <fmt>          text (default), table, csv or json.\n"
	        "  -o, --output <file>         Write report to file instead of stdout.\n"
	        "  -h, --help                  Show this help.\n"
	        "\n"
	        "Identical --iterations/--warmup/--repeats on the same machine produce\n"
	        "comparable, reproducible throughput medians. Use scripts/bench/run_benchmark.py\n"
	        "for the two-run reproducibility check and the selection comparison table.\n",
	        program);
}

static bool config_add_algorithm(bench_config *cfg, const char *token) {
	if (token == NULL || token[0] == '\0') {
		return false;
	}
	char *copy = strdup(token);
	if (copy == NULL) {
		fprintf(stderr, "bench_unified: out of memory parsing algorithms\n");
		exit(EXIT_FAILURE);
	}
	for (char *part = strtok(copy, ","); part != NULL; part = strtok(NULL, ",")) {
		if (part[0] == '\0') {
			continue;
		}
		if (cfg->algorithms_len == cfg->algorithms_cap) {
			size_t new_cap = cfg->algorithms_cap == 0 ? 16 : cfg->algorithms_cap * 2;
			const char **grown = (const char **)realloc((void *)cfg->algorithms, new_cap * sizeof(char *));
			if (grown == NULL) {
				fprintf(stderr, "bench_unified: out of memory growing algorithm list\n");
				exit(EXIT_FAILURE);
			}
			cfg->algorithms = grown;
			cfg->algorithms_cap = new_cap;
		}
		cfg->algorithms[cfg->algorithms_len++] = part;
	}
	/* Note: 'copy' is retained because stored pointers point inside it. */
	return true;
}

static bool parse_size_arg(const char *text, size_t *value) {
	if (text == NULL || text[0] == '\0') {
		return false;
	}
	char *end = NULL;
	unsigned long long parsed = strtoull(text, &end, 10);
	if (end == text || end[0] != '\0' || parsed == 0) {
		return false;
	}
	*value = (size_t)parsed;
	return true;
}

/* Like parse_size_arg but accepts zero (used for the optional warm-up). */
static bool parse_size_arg_zero_ok(const char *text, size_t *value) {
	if (text == NULL || text[0] == '\0') {
		return false;
	}
	char *end = NULL;
	unsigned long long parsed = strtoull(text, &end, 10);
	if (end == text || end[0] != '\0') {
		return false;
	}
	*value = (size_t)parsed;
	return true;
}

/* Returns the number of argv tokens consumed (1 or 2), or -1 on error. */
static int parse_option_value(int argc, char **argv, int index, const char *long_name, char short_name, const char **value) {
	const char *arg = argv[index];
	size_t long_len = strlen(long_name);
	char short_prefix[3];
	snprintf(short_prefix, sizeof(short_prefix), "-%c", short_name);

	if (strncmp(arg, "--", 2) == 0) {
		if (strncmp(arg + 2, long_name, long_len) == 0 && arg[2 + long_len] == '=') {
			*value = arg + 3 + long_len;
			return 1;
		}
		if (strcmp(arg + 2, long_name) == 0) {
			if (index + 1 >= argc) {
				fprintf(stderr, "bench_unified: option --%s requires a value\n", long_name);
				return -1;
			}
			*value = argv[index + 1];
			return 2;
		}
	} else if (short_name != '\0' && arg[0] == '-' && arg[1] == short_name) {
		if (arg[2] != '\0') {
			/* Attached form, e.g. -n50. */
			*value = arg + 2;
			return 1;
		}
		if (index + 1 >= argc) {
			fprintf(stderr, "bench_unified: option %s requires a value\n", short_prefix);
			return -1;
		}
		*value = argv[index + 1];
		return 2;
	}
	return 0;
}

static int print_algorithm_list(void) {
	for (size_t i = 0; i < OQS_KEM_algs_length; i++) {
		const char *name = OQS_KEM_alg_identifier(i);
		OQS_KEM *kem = OQS_KEM_new(name);
		printf("%-4s %-40s %s\n", "kem", name, kem != NULL ? "enabled" : "disabled");
		OQS_KEM_free(kem);
	}
	for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
		const char *name = OQS_SIG_alg_identifier(i);
		OQS_SIG *sig = OQS_SIG_new(name);
		printf("%-4s %-40s %s\n", "sig", name, sig != NULL ? "enabled" : "disabled");
		OQS_SIG_free(sig);
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	bench_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.iterations = 0; /* 0 => adaptive via batch_ms */
	cfg.batch_ms = 200;
	cfg.warmup = 20;
	cfg.repeats = 5;
	cfg.format = "text";

	for (int i = 1; i < argc; i++) {
		const char *value = NULL;
		int consumed;
		if (strcmp(argv[i], "--") == 0) {
			for (int j = i + 1; j < argc; j++) {
				config_add_algorithm(&cfg, argv[j]);
			}
			break;
		}
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			cfg.help_only = true;
			continue;
		}
		if (strcmp(argv[i], "--all") == 0) {
			cfg.run_all = true;
			continue;
		}
		if (strcmp(argv[i], "--list") == 0) {
			cfg.list_only = true;
			continue;
		}
		consumed = parse_option_value(argc, argv, i, "algorithms", 'a', &value);
		if (consumed < 0) {
			return EXIT_FAILURE;
		}
		if (consumed > 0) {
			config_add_algorithm(&cfg, value);
			i += consumed - 1;
			continue;
		}
		consumed = parse_option_value(argc, argv, i, "iterations", 'n', &value);
		if (consumed > 0) {
			if (!parse_size_arg(value, &cfg.iterations)) {
				fprintf(stderr, "bench_unified: invalid --iterations '%s'\n", value);
				return EXIT_FAILURE;
			}
			i += consumed - 1;
			continue;
		} else if (consumed < 0) {
			return EXIT_FAILURE;
		}
		consumed = parse_option_value(argc, argv, i, "batch-ms", '\0', &value);
		if (consumed > 0) {
			if (!parse_size_arg(value, &cfg.batch_ms)) {
				fprintf(stderr, "bench_unified: invalid --batch-ms '%s'\n", value);
				return EXIT_FAILURE;
			}
			i += consumed - 1;
			continue;
		} else if (consumed < 0) {
			return EXIT_FAILURE;
		}
		consumed = parse_option_value(argc, argv, i, "warmup", 'w', &value);
		if (consumed > 0) {
			if (!parse_size_arg_zero_ok(value, &cfg.warmup)) {
				fprintf(stderr, "bench_unified: invalid --warmup '%s'\n", value);
				return EXIT_FAILURE;
			}
			i += consumed - 1;
			continue;
		} else if (consumed < 0) {
			return EXIT_FAILURE;
		}
		consumed = parse_option_value(argc, argv, i, "repeats", 'r', &value);
		if (consumed > 0) {
			if (!parse_size_arg(value, &cfg.repeats)) {
				fprintf(stderr, "bench_unified: invalid --repeats '%s'\n", value);
				return EXIT_FAILURE;
			}
			i += consumed - 1;
			continue;
		} else if (consumed < 0) {
			return EXIT_FAILURE;
		}
		consumed = parse_option_value(argc, argv, i, "format", 'f', &value);
		if (consumed < 0) {
			return EXIT_FAILURE;
		}
		if (consumed > 0) {
			if (strcmp(value, "text") != 0 && strcmp(value, "table") != 0 &&
			    strcmp(value, "csv") != 0 && strcmp(value, "json") != 0) {
				fprintf(stderr, "bench_unified: unsupported --format '%s' (text|table|csv|json)\n", value);
				return EXIT_FAILURE;
			}
			cfg.format = value;
			i += consumed - 1;
			continue;
		}
		consumed = parse_option_value(argc, argv, i, "output", 'o', &value);
		if (consumed < 0) {
			return EXIT_FAILURE;
		}
		if (consumed > 0) {
			cfg.output_path = value;
			i += consumed - 1;
			continue;
		}
		if (argv[i][0] == '-') {
			fprintf(stderr, "bench_unified: unknown option '%s'\n", argv[i]);
			print_usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
		config_add_algorithm(&cfg, argv[i]);
	}

	if (cfg.help_only) {
		print_usage(stdout, argv[0]);
		return EXIT_SUCCESS;
	}

	OQS_init();
#if defined(OQS_USE_OPENSSL)
	if (OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl) != OQS_SUCCESS) {
		fprintf(stderr, "bench_unified: could not select OpenSSL RNG; continuing with default RNG\n");
	}
#endif

	if (cfg.list_only) {
		int rc = print_algorithm_list();
		OQS_destroy();
		return rc;
	}

	/* Build the final algorithm name list. */
	const char **names = NULL;
	size_t names_len = 0;
	if (cfg.run_all) {
		size_t cap = OQS_KEM_algs_length + OQS_SIG_algs_length;
		names = (const char **)bench_xalloc(cap * sizeof(char *));
		for (size_t i = 0; i < OQS_KEM_algs_length; i++) {
			names[names_len++] = OQS_KEM_alg_identifier(i);
		}
		for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
			names[names_len++] = OQS_SIG_alg_identifier(i);
		}
	} else if (cfg.algorithms_len == 0) {
		names = k_default_algorithms;
		names_len = DEFAULT_ALGORITHM_COUNT;
	} else {
		names = (const char **)cfg.algorithms;
		names_len = cfg.algorithms_len;
	}

	bench_result **results = (bench_result **)bench_xalloc(names_len * sizeof(bench_result *));
	size_t results_len = 0;
	for (size_t i = 0; i < names_len; i++) {
		const char *name = names[i];
		bench_result *res = benchmark_kem(name, &cfg);
		if (res == NULL) {
			res = benchmark_sig(name, &cfg);
		}
		if (res == NULL) {
			fprintf(stderr, "bench_unified: skipping '%s' (unknown or disabled in this build)\n", name);
			continue;
		}
		results[results_len++] = res;
	}

	if (results_len == 0) {
		fprintf(stderr, "bench_unified: no benchmarkable algorithms\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	FILE *out = stdout;
	if (cfg.output_path != NULL) {
		out = fopen(cfg.output_path, "w");
		if (out == NULL) {
			fprintf(stderr, "bench_unified: cannot open output file '%s'\n", cfg.output_path);
			OQS_destroy();
			return EXIT_FAILURE;
		}
	} else if (strcmp(cfg.format, "text") == 0) {
		print_system_info();
		fprintf(stdout, "liboqs unified benchmark\n");
		fprintf(stdout, "=========================\n");
		if (cfg.iterations > 0) {
			fprintf(stdout, "parameters: iterations=%zu (fixed) warmup=%zu repeats=%zu message_bytes=%d\n\n",
			        cfg.iterations, cfg.warmup, cfg.repeats, BENCH_MESSAGE_BYTES);
		} else {
			fprintf(stdout, "parameters: iterations=adaptive(target %zu ms/batch) warmup=%zu repeats=%zu message_bytes=%d\n\n",
			        cfg.batch_ms, cfg.warmup, cfg.repeats, BENCH_MESSAGE_BYTES);
		}
	}

	if (strcmp(cfg.format, "json") == 0) {
		print_json(out, &cfg, results, results_len);
	} else if (strcmp(cfg.format, "csv") == 0) {
		print_csv(out, &cfg, results, results_len);
	} else if (strcmp(cfg.format, "table") == 0) {
		print_wide_table(out, results, results_len);
	} else {
		print_text_blocks(out, results, results_len);
		print_wide_table(out, results, results_len);
	}

	if (out != stdout) {
		fclose(out);
	}

	for (size_t i = 0; i < results_len; i++) {
		for (int op = 0; op < BENCH_OP_COUNT; op++) {
			OQS_MEM_insecure_free(results[i]->samples[op]);
		}
		OQS_MEM_insecure_free(results[i]);
	}
	OQS_MEM_insecure_free(results);
	if (cfg.run_all) {
		OQS_MEM_insecure_free((void *)names);
	}
	OQS_destroy();
	return EXIT_SUCCESS;
}
