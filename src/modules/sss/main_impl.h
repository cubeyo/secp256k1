/***********************************************************************
 * Copyright (c) 2020-2021 JK Zhou                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_SSS_MAIN_
#define _SECP256K1_MODULE_SSS_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_sss.h"

#include "scalar_impl.h"

#define SCALA_AT(scratch, i) (((secp256k1_scalar*)scratch->data)[i])

int secp256k1_sss_share_create(
    const secp256k1_context* ctx,
    unsigned char out[][32],
    const unsigned char *secret,
    /* const unsigned char coefficients[][32], */
    unsigned char coefficients[][32],
    size_t threshold,
    size_t share_count,
    secp256k1_scratch_space * coefficient_buffer
) {
    size_t i, j;
    int ret = 1;
    int overflow = 0;
    secp256k1_scalar share, x;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(threshold > 0);
    ARG_CHECK(share_count > threshold);
    ARG_CHECK(out != NULL);
    ARG_CHECK(secret != NULL);
    ARG_CHECK(coefficients != NULL);
    VERIFY_CHECK(coefficient_buffer != NULL);

    /* prepare polynomial coefficients */
    secp256k1_scalar_set_b32(&SCALA_AT(coefficient_buffer, 0), secret, &overflow);
    ret &= !overflow;
    for(i = 1; i <= threshold; i++) {
        secp256k1_scalar_set_b32(&SCALA_AT(coefficient_buffer, i), coefficients[i - 1], &overflow);
        ret &= !overflow;
    }

    for(i = 0; i < share_count; i++) {
        /* evaluate polynomial */
        secp256k1_scalar_set_int(&x, i + 1);
        secp256k1_scalar_cmov(&share, &SCALA_AT(coefficient_buffer, threshold), ret);
        for(j = threshold - 1; j < threshold; j--) {
            secp256k1_scalar_mul(&share, &share, &x);
            secp256k1_scalar_add(&share, &share, &SCALA_AT(coefficient_buffer, j)); 
        }
        secp256k1_scalar_get_b32(out[i], &share);
    }
    secp256k1_scalar_clear(&share);
    secp256k1_scalar_clear(&x);
    memset(coefficient_buffer->data, 0, sizeof(secp256k1_scalar) * (threshold + 1));
    return ret;
}

int secp256k1_sss_get_additive_share(
    const secp256k1_context* ctx,
    unsigned char* out,
    const unsigned char* share,
    const size_t * parties,
    size_t threshold,
    size_t index
) {
    secp256k1_scalar nag_xi, denum, party_i, r;
    size_t i;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(out != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(parties != NULL);
    ARG_CHECK(threshold > 0);
    ARG_CHECK(index > 0);
    for(i = 0; i <= threshold; i++) {
        ARG_CHECK(parties[i] > 0);
    }
    
    secp256k1_scalar_set_b32(&r, share, &overflow);
    ret &= !overflow;

    secp256k1_scalar_set_int(&nag_xi, index);
    secp256k1_scalar_negate(&nag_xi, &nag_xi);
    secp256k1_scalar_set_int(&denum, 1);
    for(i = 0; i <= threshold; i++) {
        if(parties[i] == index) {
            continue;
        }
        secp256k1_scalar_set_int(&party_i, parties[i]);
        secp256k1_scalar_mul(&r, &r, &party_i);
        secp256k1_scalar_add(&party_i, &party_i, &nag_xi);
        secp256k1_scalar_mul(&denum, &denum, &party_i);
    }
    secp256k1_scalar_inverse(&denum, &denum);
    secp256k1_scalar_mul(&r, &r, &denum);
    if(ret) {
        secp256k1_scalar_get_b32(out, &r);
    }
    secp256k1_scalar_clear(&nag_xi);
    secp256k1_scalar_clear(&denum);
    secp256k1_scalar_clear(&party_i);
    secp256k1_scalar_clear(&r);
    return ret;
}

#endif