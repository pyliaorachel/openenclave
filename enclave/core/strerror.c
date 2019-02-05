// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/string.h>
#include <openenclave/enclave.h>

/* Use OE STDC errno defs for MUSL __strerror.h */
#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <openenclave/elibc/errno.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

typedef struct _error_info
{
    int errnum;
    const char* message;
} error_info_t;

static error_info_t _errors[] = {
#define E(errno, message) {errno, message},
#include "../../3rdparty/musl/musl/src/errno/__strerror.h"
};

static size_t _num_errors = sizeof(_errors) / sizeof(_errors[0]);

static const char _unknown[] = "Unknown error";

char* oe_strerror(int errnum)
{
    for (size_t i = 0; i < _num_errors; i++)
    {
        if (_errors[i].errnum == errnum)
            return (char*)_errors[i].message;
    }

    return (char*)_unknown;
}

int oe_strerror_r(int errnum, char* buf, size_t buflen)
{
    const char* str = NULL;

    for (size_t i = 0; i < _num_errors; i++)
    {
        if (_errors[i].errnum == errnum)
        {
            str = _errors[i].message;
            break;
        }
    }

    if (!str)
        str = _unknown;

    return oe_strlcpy(buf, str, buflen) >= buflen ? OE_ERANGE : 0;
}