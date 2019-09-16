// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "arena.h"
#include <openenclave/bits/safemath.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include <string.h>

// the per-thread shared memory pool
static __thread shared_memory_arena_t arena = {0};

// default shared memory pool capacity is 1 mb
static size_t capacity = 1024 * 1024;

static const size_t max_capacity = 1 << 30;

void* oe_allocate_arena(size_t capacity);
void oe_deallocate_arena(void* buffer);

bool oe_configure_arena_capacity(size_t cap)
{
    if (cap > max_capacity)
    {
        return false;
    }
    capacity = cap;
    return true;
}

void* oe_arena_malloc(size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t total_size = 0;
    const size_t align = OE_EDGER8R_BUFFER_ALIGNMENT;

    // Create the anera if it hasn't been created.
    if (arena.buffer == NULL)
    {
        void* buffer = oe_allocate_arena(capacity);
        if (buffer == NULL)
            return NULL;
        arena.buffer = (uint8_t*)buffer;
        arena.capacity = capacity;
        arena.used = 0;
    }

    // Round up to the nearest alignment size.
    total_size = oe_round_up_to_multiple(size, align);

    // check for overflow
    if (total_size < size)
        return NULL;

    // check for capacity
    size_t used_after;
    OE_CHECK(oe_safe_add_sizet(arena.used, total_size, &used_after));

    // Ok if the incoming malloc puts us below the capacity.
    if (used_after <= arena.capacity)
    {
        uint8_t* addr = arena.buffer + arena.used;
        arena.used = used_after;
        return addr;
    }

done:
    return NULL;
}

void* oe_arena_calloc(size_t num, size_t size)
{
    size_t total = 0;
    if (oe_safe_mul_sizet(num, size, &total) != OE_OK)
        return NULL;

    void* ptr = oe_arena_malloc(total);
    if (ptr != NULL)
    {
        memset(ptr, 0, total);
    }
    return ptr;
}

void oe_arena_free_all()
{
    arena.used = 0;
}

// Free all shared memory pools in the global list
void oe_teardown_arena()
{
    if (arena.buffer != NULL)
        oe_deallocate_arena(arena.buffer);
    memset(&arena, 0, sizeof(arena));
}
