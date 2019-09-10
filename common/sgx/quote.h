// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QUOTE_H
#define _OE_COMMON_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>

OE_EXTERNC_BEGIN

oe_result_t oe_verify_quote_internal(
    const uint8_t* enc_quote,
    size_t quote_size,
    const uint8_t* enc_pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* enc_pck_crl,
    size_t enc_pck_crl_size,
    const uint8_t* enc_tcb_info_json,
    size_t enc_tcb_info_json_size);

/*!
 * Retrieves certifate chain from the quote.
 *
 * Caller is responsible for deallocating memory in pck_cert_chain.
 *
 * \param quote[in] Input quote.
 * \param quote_size[in] The size of the quote.
 * \param pem_pck_certifcate[out] Pointer to the quote where the certificate PCK
 * starts. \param pem_pck_certificate_size[out] Size of the PCK certificate.
 * \param pck_cert_chain[out] Reference to an instance of oe_cert_chain_t where
 * to store the chain.
 */
oe_result_t oe_get_quote_cert_chain_internal(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t** pem_pck_certificate,
    size_t* pem_pck_certificate_size,
    oe_cert_chain_t* pck_cert_chain);

OE_EXTERNC_END

#endif // _OE_COMMON_QUOTE_H
