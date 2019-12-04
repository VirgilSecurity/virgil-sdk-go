/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the fixed A matrix as well as the function to generate it.
 */

#ifndef A_FIXED_H
#define A_FIXED_H

#include "parameters.h"
#include <stddef.h>

/**
 * The fixed A matrix for use inside with the non-ring algorithm when τ=1.
 * This matrix is generated by `create_A_fixed()`.
 */
extern uint16_t *A_fixed;

/**
 * The size (number of elements) of the fixed A matrix, set with `create_A_fixed()`.
 */
extern size_t A_fixed_len;

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Function to generate a fixed A matrix from the given seed.
     *
     * @param[in] seed   the seed to use to generate the fixed A matrix (kappa_bytes bytes)
     * @param[in] params the algorithm parameters for which the fixed A matrix should be generated
     * @return __0__ in case of success
     */
    int create_A_fixed(const unsigned char *seed, const parameters *params);

#ifdef __cplusplus
}
#endif

#endif /* A_FIXED_H */
