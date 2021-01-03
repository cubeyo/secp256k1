/***********************************************************************
 * Copyright (c) 2020-2021 JK Zhou                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_sss.h"
#include "field_impl.h"
#include "scalar_impl.h"

#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context* ctx;
    size_t threshold;
    size_t share_count;
    unsigned char secret[32];
    unsigned char (*out_shares)[32];
    unsigned char (*coefficients)[32];
    secp256k1_scratch_space * coefficients_buffer;
} bench_sss_data;

static void bench_sss_setup(size_t threshold, size_t share_count, void* arg) {
    size_t i, j;
    bench_sss_data *data = (bench_sss_data*)arg;

    data->threshold = threshold;
    data->share_count = share_count;
    data->out_shares = (unsigned char (*)[32])malloc(32 * share_count);
    data->coefficients = (unsigned char (*)[32])malloc(32 * threshold);
    for(i = 0; i < 32; i++) {
        data->secret[i] = i + 1;
    }
    for(i = 0; i < threshold; i++) {
        for(j = 0; j < 32; j++) {
            data->coefficients[i][j] = ((i << 5) | j) + 65;
        }
    }
    data->coefficients_buffer = secp256k1_scratch_space_create(
        data->ctx, sizeof(secp256k1_scalar) * (threshold + 1));
}

static void bench_sss_setup_1_2(void* arg) { bench_sss_setup(1, 2, arg); }
static void bench_sss_setup_2_3(void* arg) { bench_sss_setup(2, 3, arg); }
static void bench_sss_setup_3_5(void* arg) { bench_sss_setup(3, 5, arg); }
static void bench_sss_setup_5_8(void* arg) { bench_sss_setup(5, 8, arg); }
static void bench_sss_setup_10_20(void* arg) { bench_sss_setup(10, 20, arg); }

static void bench_sss_setup_20_30(void* arg) { bench_sss_setup(20, 30, arg); }
static void bench_sss_setup_20_40(void* arg) { bench_sss_setup(20, 40, arg); }
static void bench_sss_setup_20_60(void* arg) { bench_sss_setup(20, 60, arg); }
static void bench_sss_setup_20_80(void* arg) { bench_sss_setup(20, 80, arg); }

static void bench_sss_teardown(void *arg, int iters) {
    bench_sss_data *data = (bench_sss_data*)arg;
    iters = iters; /* to avoid compiler unused-parameter warning */
    secp256k1_scratch_space_destroy(data->ctx, data->coefficients_buffer);
    free(data->out_shares);
    free(data->coefficients);
}

static void bench_sss_run(void* arg, int iters) {
    int i;
    bench_sss_data *data = (bench_sss_data*)arg;
    for (i = 0; i < iters; i++) {
    CHECK(secp256k1_sss_share_create(
        data->ctx, data->out_shares, data->secret, data->coefficients,
        data->threshold, data->share_count, data->coefficients_buffer));
    }
}

static void bench_share_get_setup(size_t threshold, size_t share_count, void* arg) {
    bench_sss_data *data = (bench_sss_data*)arg;
    bench_sss_setup(threshold, share_count, arg);
    CHECK(secp256k1_sss_share_create(
        data->ctx, data->out_shares, data->secret, data->coefficients,
        data->threshold, data->share_count, data->coefficients_buffer));
}

static void bench_share_get_setup_1_2(void* arg) { bench_share_get_setup(1, 2, arg); }
static void bench_share_get_setup_2_3(void* arg) { bench_share_get_setup(2, 3, arg); }
static void bench_share_get_setup_3_5(void* arg) { bench_share_get_setup(3, 5, arg); }
static void bench_share_get_setup_5_8(void* arg) { bench_share_get_setup(5, 8, arg); }
static void bench_share_get_setup_10_20(void* arg) { bench_share_get_setup(10, 20, arg); }

static void bench_share_get_setup_20_30(void* arg) { bench_share_get_setup(20, 30, arg); }
static void bench_share_get_setup_20_40(void* arg) { bench_share_get_setup(20, 40, arg); }
static void bench_share_get_setup_20_60(void* arg) { bench_share_get_setup(20, 60, arg); }
static void bench_share_get_setup_20_80(void* arg) { bench_share_get_setup(20, 80, arg); }
static void bench_share_get_teardown(void *arg, int iters) {
    bench_sss_teardown(arg, iters);
}

static void bench_share_get_run(void* arg, int iters) {
    size_t i, j;
    unsigned char (*res)[32];
    size_t *parties;
    int ret = 1;

    bench_sss_data* data = (bench_sss_data*)arg;
    parties = (size_t*)malloc(sizeof(size_t) * (data->threshold + 1));
    res = (unsigned char (*)[32])malloc(32 * (data->threshold + 1));

    /* split iters into iters / (threshold + 1) round 
     * and run (threshold + 1) recoveries in each round
     * */
    for (i = 0; i < iters / (data->threshold + 1); i++) {
        /* prepare party ids for current loop */
        for(j = 0; j < data->threshold + 1; j++) {
            parties[j] = 1 + (i + j) % data->share_count;
        }
        
        /* for each selected party, recover it's share */
        for(j = 0; j < data->threshold + 1; j++) {
            CHECK(secp256k1_sss_get_additive_share(
                data->ctx, res[j], data->out_shares[parties[j] - 1],
                parties, data->threshold, parties[j]));
        }
        for(j = 1; j < data->threshold + 1; j++) {
            ret = ret && secp256k1_ec_privkey_tweak_add(data->ctx, res[0], res[j]);
        }
        CHECK(secp256k1_memcmp_var(res[0], data->secret, 32) == 0);
    }
    free(parties);
    free(res);
}

int main(void) {
    bench_sss_data data;
    int iters;
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    iters = get_iters(20000);
    run_benchmark("shamir_secret_sharing_1_2", bench_sss_run, bench_sss_setup_1_2, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_2_3", bench_sss_run, bench_sss_setup_2_3, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_3_5", bench_sss_run, bench_sss_setup_3_5, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_5_8", bench_sss_run, bench_sss_setup_5_8, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_10_20", bench_sss_run, bench_sss_setup_10_20, bench_sss_teardown, &data, 10, iters);

    run_benchmark("shamir_secret_sharing_20_30", bench_sss_run, bench_sss_setup_20_30, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_20_40", bench_sss_run, bench_sss_setup_20_40, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_20_60", bench_sss_run, bench_sss_setup_20_60, bench_sss_teardown, &data, 10, iters);
    run_benchmark("shamir_secret_sharing_20_80", bench_sss_run, bench_sss_setup_20_80, bench_sss_teardown, &data, 10, iters);

    run_benchmark("recover_secret_share_1_2", bench_share_get_run, bench_share_get_setup_1_2, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_2_3", bench_share_get_run, bench_share_get_setup_2_3, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_3_5", bench_share_get_run, bench_share_get_setup_3_5, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_5_8", bench_share_get_run, bench_share_get_setup_5_8, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_10_20", bench_share_get_run, bench_share_get_setup_10_20, bench_share_get_teardown, &data, 10, iters);

    run_benchmark("recover_secret_share_20_30", bench_share_get_run, bench_share_get_setup_20_30, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_20_40", bench_share_get_run, bench_share_get_setup_20_40, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_20_60", bench_share_get_run, bench_share_get_setup_20_60, bench_share_get_teardown, &data, 10, iters);
    run_benchmark("recover_secret_share_20_80", bench_share_get_run, bench_share_get_setup_20_80, bench_share_get_teardown, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
