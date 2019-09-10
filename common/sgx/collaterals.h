// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_OE_COLLATERALS_H
#define _OE_COMMON_OE_COLLATERALS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

oe_result_t oe_get_collaterals_internal(
    uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size);

OE_EXTERNC_END

#endif /* _OE_COMMON_OE_COLLATERALS_H */
