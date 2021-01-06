/***********************************************************************
 * Copyright (c) 2020-2021 JK Zhou                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_SSS_TESTS_
#define _SECP256k1_MODULE_SSS_TESTS_

#include "secp256k1_sss.h"

/* threshold = 2
 * share_count = 5
 */
void test_secret_sharing(size_t threshold, size_t share_count, size_t selected_parties[]) {
    unsigned char secret[32];
    unsigned char (*out_shares)[32];
    unsigned char (*coefficients)[32];
    unsigned char (*test_shares)[32];
    size_t i;
    int ret;
    secp256k1_scratch_space * coefficients_buffer;

    out_shares = (unsigned char (*)[32])malloc(32 * share_count);
    coefficients = (unsigned char (*)[32])malloc(32 * threshold);
    test_shares = (unsigned char (*)[32])malloc(32 * (threshold + 1));
    coefficients_buffer = secp256k1_scratch_space_create(
        ctx, sizeof(secp256k1_scalar) * (threshold + 1));
    secp256k1_testrand256(secret);

    for(i = 0; i < threshold; i++) {
        secp256k1_testrand256(coefficients[i]);
    }

    ret = secp256k1_sss_share_create(ctx, out_shares, secret, coefficients, threshold, share_count, coefficients_buffer);
    for(i = 0; i < threshold + 1; i++) {
        ret = ret && secp256k1_sss_get_additive_share(ctx, test_shares[i], out_shares[selected_parties[i] - 1], selected_parties, threshold, selected_parties[i]);
    }

    for(i = 1; i < threshold + 1; i++) {
        ret = ret && secp256k1_ec_privkey_tweak_add(ctx, test_shares[0], test_shares[i]);
    }
    CHECK(ret == 1);
    CHECK(secp256k1_memcmp_var(secret, test_shares[0], 32) == 0);
    free(out_shares);
    free(coefficients);
    free(test_shares);
    secp256k1_scratch_space_destroy(ctx, coefficients_buffer);
}

void run_sss_tests(void) {
    unsigned int i;

    size_t selected_parties_2_1[][2] = {
        {1,2},
        {2,1}
    };

    size_t selected_parties_3_1[][2] = {
        {1,2}, {1,3}, {2,3}, {3,1}
    };

    size_t selected_parties_4_2[][3] = {
        {1,2,3}, {1,2,4}, {1,3,4}, {2,3,4}
    };
    
    size_t selected_parties_5_2[][3] = {
        {1,2,3}, {1,2,4}, {1,2,5},
        {2,3,4}, {2,3,5},
        {3,4,5},
        {5,4,3}, {3,2,1}, {5,1,2}
    };

    for(i = 0; i < sizeof(selected_parties_2_1) / sizeof(size_t) / 2; i++) {
        test_secret_sharing(1, 2, selected_parties_2_1[i]);
    }

    for(i = 0; i < sizeof(selected_parties_3_1) / sizeof(size_t) / 2; i++) {
        test_secret_sharing(1, 3, selected_parties_3_1[i]);
    }

    for(i = 0; i < sizeof(selected_parties_4_2) / sizeof(size_t) / 3; i++) {
        test_secret_sharing(2, 4, selected_parties_4_2[i]);
    }

    for(i = 0; i < sizeof(selected_parties_5_2) / sizeof(size_t) / 3; i++) {
        test_secret_sharing(2, 5, selected_parties_5_2[i]);
    }
}
#endif