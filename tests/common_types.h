#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERROR_INVALID_PARAMS = -1,
    ECLIPTIX_ERROR_CRYPTO_FAILURE = -2,
    ECLIPTIX_ERROR_VERIFICATION_FAILED = -3,
    ECLIPTIX_ERROR_INIT_FAILED = -4
} ecliptix_result_t;