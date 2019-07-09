// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _VE_ENCLAVE_GLOBALS_H
#define _VE_ENCLAVE_GLOBALS_H

#include "common.h"

/* The .tdata section of this process (sent from the host). */
extern size_t __ve_tdata_rva;
extern size_t __ve_tdata_size;
extern size_t __ve_tdata_align;

/* The .tbss section of this process (sent from the host). */
extern size_t __ve_tbss_rva;
extern size_t __ve_tbss_size;
extern size_t __ve_tbss_align;

/* Holds relative virtual address of this variable itself (from the host). */
extern uint64_t __ve_self;

/* The relative-virtual address of the first program segment (ELF header). */
extern uint64_t __ve_base_rva;

#endif /* _VE_ENCLAVE_GLOBALS_H */
