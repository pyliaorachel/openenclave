// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESS_H
#define _OE_SWITCHLESS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>

typedef struct _host_worker_thread_context
{
    volatile oe_call_host_function_args_t* call_arg;
    volatile bool is_stopping;
    oe_enclave_t* enclave;
} oe_host_worker_context_t;

typedef struct _oe_switchless_call_manager
{
    oe_host_worker_context_t* host_worker_contexts;
    oe_thread_t* host_worker_threads;
    size_t num_host_workers;
} oe_switchless_call_manager_t;

oe_result_t oe_start_switchless_manager(
    oe_enclave_t* enclave,
    size_t num_host_workers);

oe_result_t oe_stop_switchless_manager(oe_enclave_t* enclave);

#endif /* _OE_SWITCHLESS_H */
