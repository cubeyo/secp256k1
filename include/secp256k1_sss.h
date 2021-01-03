#ifndef SECP256K1_SSS_H
#define SECP256K1_SSS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Create shamir shares for a secret key with given polynomial coefficients in secp256k1 finite field.
 *
 *  Shamir secret sharing can share a secret key between n parties with threshold t.
 *  Secret key can not be reconstructed if and only if more than t parties reveal 
 *  their secret shares.
 * 
 *  This implementation uses Xi = i + 1 as x-coordinate for party i (start from 0). So the result share
 *  point for each party can be expressed by a one-dimension array with only y-coordinate.
 *  
 *  Returns: 1 if secret key is succesfully shared, 0 otherwise.
 * 
 *  Args:   ctx:                pointer to a context object (cannot be NULL).
 *  Out:    out:                pointer to a two dimension array with space of {share_count} * 32 bytes.
 *                              each 32-byte data at position i (start from 0) represents a secret point
 *                              (Xi, Yi) = (i + 1, out[i]) for party-i. (cannot be NULL).
 *  In:     secret              pointer to a 32-byte secret number to be shared (cannot be NULL).
 *          coefficients:       pointer to a two dimension array with {threshold} random coefficients
 *                              for polynomial. each coefficient is a 32-byte unsigned char array.
 *                              coefficient at position i (start from 0) will be multipled by x^(i + 1).
 *                              (cannot be NULL).
 *          threshold:          threshold for reconstructing share. secret key can be reconstructed only 
 *                              with party count > threshold.
 *          share_count:        total number of parties to hold shares.
 *          coefficients_buffer:buffer to save scalar representation for coefficients. should contain space
 *                              for {threshold + 1} scalars. all the buffered data will be cleared before
 *                              return (cannot be NULL).
 * 
 * coefficients buffer can be allocated using:
 * secp256k1_scratch_space_create(ctx, sizeof(secp256k1_scalar) * (threshold + 1));
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_sss_share_create(
    const secp256k1_context* ctx,
    unsigned char out[][32],
    const unsigned char *secret,
    unsigned char coefficients[][32],
    size_t threshold,
    size_t share_count,
    secp256k1_scratch_space * coefficients_buffer
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);

/** Get additive share which can be used to reconstruct original secret value by add operation on finite
 *  field of secp256k1.
 *
 *  Additive share is defined to be L*share, where L is the lagrange coefficient for party's share, based
 *  on participant party ids when reconstructing secret.
 *  
 *  Returns: 0 if the arguments are invalid. 1 otherwise.
 * 
 *  Args:   ctx:        pointer to a context object (cannot be NULL).
 *  Out:    out:        pointer to a 32-byte array for addtive key result (cannot be NULL).
 *  In:     share       pointer to a 32-byte secret share (cannot be NULL).
 *          parties     pointer to an integer array with {threshold + 1} party id items. current
 *                      party id need also be included. (cannot be NULL).
 *          threshold:  threshold for reconstructing share.
 *          index:      current party id.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_sss_get_additive_share(
    const secp256k1_context* ctx,
    unsigned char* out,
    const unsigned char* share,
    const size_t * parties,
    size_t threshold,
    size_t index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif