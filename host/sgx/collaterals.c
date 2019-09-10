// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/report.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/sgx/collaterals.h"
#include "sgxquoteprovider.h"

oe_result_t oe_get_collaterals(
    oe_enclave_t* enclave,
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_t* parsed_report = NULL;
    oe_report_header_t* header = NULL;

    OE_TRACE_INFO("Enter host call %s\n", __FUNCTION__);

    if ((collaterals_buffer == NULL) || (collaterals_buffer_size == NULL))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    *collaterals_buffer = NULL;
    *collaterals_buffer_size = 0;

    OE_CHECK(oe_initialize_quote_provider());

    // Get quote.  This is needed in order to get the uri for the CRL.
    OE_CHECK(oe_get_report(
        enclave,
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        0,
        (uint8_t**)&remote_report,
        &report_size));
    header = (oe_report_header_t*)remote_report;

    OE_CHECK(
        oe_verify_report(enclave, remote_report, report_size, parsed_report));

    OE_CHECK(oe_get_collaterals_internal(
        header->report,
        header->report_size,
        collaterals_buffer,
        collaterals_buffer_size));

    result = OE_OK;
done:
    if (remote_report)
        oe_free_report(remote_report);

    OE_TRACE_INFO(
        "Exit host call %s: %d(%s)\n",
        __FUNCTION__,
        result,
        oe_result_str(result));

    return result;
}

void oe_cleanup_collaterals(uint8_t* collaterals_buffer)
{
    if (collaterals_buffer)
    {
        oe_collaterals_t* collaterals =
            (oe_collaterals_t*)(collaterals_buffer + OE_COLLATERALS_HEADER_SIZE);

        oe_cleanup_qe_identity_info_args(&collaterals->qe_id_info);
        oe_cleanup_get_revocation_info_args(&collaterals->revocation_info);

        free(collaterals_buffer);
    }
}
