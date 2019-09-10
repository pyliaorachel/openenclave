// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "../common.h"

#include "collaterals.h"
#include "qeidentity.h"
#include "quote.h"
#include "revocation.h"

oe_result_t oe_get_collaterals_internal(
    uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* buffer = NULL;
    oe_collaterals_header_t* header = NULL;
    oe_collaterals_t* collaterals = NULL;

    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    oe_cert_t intermediate_cert = {0};

    OE_TRACE_INFO("Enter call %s\n", __FUNCTION__);

    if ((collaterals_buffer == NULL) || (collaterals_buffer_size == NULL))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    *collaterals_buffer = NULL;
    *collaterals_buffer_size = 0;

    buffer = (uint8_t*)oe_calloc(
        1, OE_COLLATERALS_HEADER_SIZE + OE_COLLATERALS_SIZE);
    if (buffer == NULL)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    header = (oe_collaterals_header_t*)buffer;
    collaterals = (oe_collaterals_t*)(buffer + OE_COLLATERALS_HEADER_SIZE);

    // Collateral header initialization
    header->id_version = OE_COLLATERALS_HEADER_VERSION;
    header->collaterals_size = OE_COLLATERALS_SIZE;

    //
    // Get the uri from the quote certificates, and then get the
    // CRL (oe_get_revocation_info_from_certs)
    //

    // Get PCK cert chain from the quote.
    OE_CHECK(oe_get_quote_cert_chain_internal(
        remote_report,
        remote_report_size,
        &pem_pck_certificate,
        &pem_pck_certificate_size,
        &pck_cert_chain));

    // Fetch leaf and intermediate certificates.
    OE_CHECK(oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert));
    OE_CHECK(oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert));

    // Get revocation information
    OE_CHECK(oe_get_revocation_info_from_certs(
        &leaf_cert, &intermediate_cert, &(collaterals->revocation_info)));

    //
    // QE identify info
    //
    result = oe_get_qe_identity_info(&(collaterals->qe_id_info));
    if (OE_QUOTE_PROVIDER_CALL_ERROR != result && OE_OK != result)
    {
        OE_RAISE_MSG(
            result,
            "oe_get_qe_identity_info returned unexpected result: %s.",
            oe_result_str(result));
    }

    // TODO: Application specific collaterals
    collaterals->app_collaterals_size = 0;

    result = OE_OK;
done:
    oe_cert_free(&leaf_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_chain_free(&pck_cert_chain);

    if (result == OE_OK)
    {
        *collaterals_buffer = buffer;
        *collaterals_buffer_size =
            OE_COLLATERALS_HEADER_SIZE + OE_COLLATERALS_SIZE;
    }
    else if (buffer)
    {
        oe_cleanup_get_revocation_info_args(&(collaterals->revocation_info));
        oe_cleanup_qe_identity_info_args(&(collaterals->qe_id_info));

        oe_free(buffer);
    }

    OE_TRACE_INFO(
        "Exit call %s: %d(%s)\n", __FUNCTION__, result, oe_result_str(result));

    return result;
}