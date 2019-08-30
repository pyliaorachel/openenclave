// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file host.h
 *
 * This file defines the programming interface for developing host applications.
 *
 */
#ifndef _OE_HOST_H
#define _OE_HOST_H

#ifdef _OE_ENCLAVE_H
#error "enclave.h and host.h must not be included in the same compilation unit."
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bits/defs.h"
#include "bits/report.h"
#include "bits/result.h"
#include "bits/types.h"
#include "host_verify.h"

OE_EXTERNC_BEGIN

/**
 *  Flag passed into oe_create_enclave to run the enclave in debug mode.
 *  The flag allows the enclave to be created without the enclave binary
 *  being signed. It also gives a developer permission to debug the process
 *  and get access to enclave memory. What this means is ** DO NOT SHIP
 *  CODE WITH THE OE_ENCLAVE_FLAG_DEBUG ** because it is unsecure. What
 *  it does give is the ability to develop your enclave more easily. Before
 *  you ship the code you need to have a proper code signing story for the
 *  enclave shared library.
 */
#define OE_ENCLAVE_FLAG_DEBUG 0x00000001u

/**
 *  Flag passed into oe_create_enclave to run the enclave in simulation mode.
 */
#define OE_ENCLAVE_FLAG_SIMULATE 0x00000002u

/**
 *  Flag passed into oe_create_enclave to enable the enclave with switchless
 *  calls. A switchless call is a function invocation from the trusted world to
 *  the untrusted world, or vice versa, without context switches and transition
 *  of the execution mode. Typically the caller posts the job to a shared
 *  memory buffer accessible by both the trusted world and the untrusted world,
 *  and a workers in the other world takes the job and posts the result, which
 *  is retrieved by the caller.
 */
#define OE_ENCLAVE_FLAG_CONTEXT_SWITCHLESS 0x00000004u

/**
 * @cond DEV
 */
#define OE_ENCLAVE_FLAG_RESERVED                          \
    (~(OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE | \
       OE_ENCLAVE_FLAG_CONTEXT_SWITCHLESS))
/**
 * @endcond
 */

/**
 * Type of each function in an ocall-table.
 */
typedef void (*oe_ocall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * Create an enclave from an enclave image file.
 *
 * This function creates an enclave from an enclave image file. On successful
 * return, the enclave is fully initialized and ready to use.
 *
 * @param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the **oecore** library and signed by the
 * **oesign** tool.
 *
 * @param type The type of enclave supported by the enclave image file.
 *     - OE_ENCLAVE_TYPE_SGX - An SGX enclave
 *
 * @param flags These flags control how the enclave is run.
 *     It is the bitwise OR of zero or more of the following flags
 *     - OE_ENCLAVE_FLAG_SIMULATE - runs the enclave in simulation mode
 *     - OE_ENCLAVE_FLAG_DEBUG - runs the enclave in debug mode.
 *                               DO NOT SHIP CODE with this flag
 *
 * @param config Additional enclave creation configuration data for the specific
 * enclave type.
 *
 * @param config_size The size of the **config** data buffer in bytes.
 *
 * @param ocall_table Pointer to table of ocall functions generated by
 * oeedger8r.
 *
 * @param ocall_table_size The size of the **ocall_table**.
 *
 * @param enclave This points to the enclave instance upon success.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_create_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    oe_enclave_t** enclave);

/**
 * Terminate an enclave and reclaims its resources.
 *
 * This function terminates an enclave and reclaims its resources. This
 * involves unmapping the memory that was mapped by **oe_create_enclave()**.
 * Once this is performed, the enclave can no longer be accessed.
 *
 * @param enclave The instance of the enclave to be terminated.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_terminate_enclave(oe_enclave_t* enclave);

#if (OE_API_VERSION < 2)
#error "Only OE_API_VERSION of 2 is supported"
#else
#define oe_get_report oe_get_report_v2
#endif

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation.
 *
 * @param[in] enclave The instance of the enclave that will generate the report.
 * @param[in] flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param[in] opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param[in] opt_params_size The size of the **opt_params** buffer.
 * @param[out] report_buffer This points to the resulting report upon success.
 * @param[out] report_buffer_size This is set to the size of the report buffer
 * on success.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v2(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

/**
 * Frees a report buffer obtained from oe_get_report.
 *
 * @param[in] report_buffer The report buffer to free.
 */
void oe_free_report(uint8_t* report_buffer);

#if (OE_API_VERSION < 2)
#error "Only OE_API_VERSION of 2 is supported"
#else
#define oe_get_target_info oe_get_target_info_v2
#endif

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * @param[in] report The report returned by **oe_get_report**.
 * @param[in] report_size The size of **report** in bytes.
 * @param[out] target_info_buffer This points to the platform specific data
 * upon success.
 * @param[out] target_info_size This is set to
 * the size of **target_info_buffer** on success.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size);

/**
 * Frees a target info obtained from oe_get_target_info.
 *
 * @param[in] target_info_buffer The target info to free.
 */
void oe_free_target_info(void* target_info_buffer);

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report The **oe_report_t** structure to populate with the
 * report
 * properties in a standard format. The *parsed_report* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Verify the integrity of the report and its signature.
 *
 * This function verifies that the report signature is valid. If the report is
 * local, it verifies that it is correctly signed by the enclave
 * platform. If the report is remote, it verifies that the signing authority is
 * rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param enclave The instance of the enclave that will be used to
 * verify a local report. For remote reports, this parameter can be NULL.
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Returns a public key that is associated with the identity of the enclave
 * and the specified policy.
 *
 * @param enclave The enclave handle.
 * @param seal_policy The policy for the identity properties used to derive
 * the key.
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested public key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 * @param key_info Optional pointer to a buffer for the enclave-specific key
 * information which can be used to retrieve the same key later on a newer
 * security version.
 * @param key_info_size On success, this contains the size of key_info.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY There is no memory available.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_enclave_t* enclave,
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Returns a public key that is associated with the identity of the enclave.
 *
 * @param enclave The enclave handle.
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_info The enclave-specific key information to derive the key.
 * @param key_info_size The size of the key_info buffer.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested public key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN The platform specific data has an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN The platform specific data has an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME The platform specific data has an invalid KEYNAME.
 */
oe_result_t oe_get_public_key(
    oe_enclave_t* enclave,
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Frees the given key and/or key info. Before freeing, this function will
 * zero out the key buffers to avoid leaking any confidential data.
 *
 * @param key_buffer If not NULL, the key buffer to free.
 * @param key_buffer_size The size of key_buffer.
 * @param key_info If not NULL, the key info to free.
 * @param key_info_size The size of key_info.
 */
void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size);

OE_EXTERNC_END

#endif /* _OE_HOST_H */
