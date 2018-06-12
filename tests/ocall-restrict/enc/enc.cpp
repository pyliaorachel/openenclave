// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

static int counter;

/*
   Call host via OCalls with different ECall-restrictions. The host
   will attempt to re-enter via ECalls. Check results.

   The argPtr is shared w/ the host on purpose, both for communicating the
   function-call arguments (in the format oe_ocall_function() provides them),
   as well as for return values.

 */
OE_ECALL void Test(void* argPtr)
{
    oe_result_t res;
    TestORArgs* ta = (TestORArgs*)argPtr;
    oe_call_host_args_t* cha = &ta->callHost;

    printf("%s(): Called, ta=%p\n", __FUNCTION__, ta);

    /* Perform regular ocall w/ ecall. We mimic oe_ocall_function() and use
     * internal knowledge of it to pass OE_OCALL_FLAG_NOT_REENTRANT later. */
    cha->args = argPtr;
    strcpy(cha->func, "TestEcall");

    printf("%s(): OCALL...\n", __FUNCTION__);
    res = oe_ocall(OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, 0);
    printf(
        "%s(): OCALL returned. res=%x, ta->result=%x, counter=%x\n",
        __FUNCTION__,
        res,
        ta->result,
        counter);
    OE_TEST(res == OE_OK);
    OE_TEST(ta->result == OE_OK);
    OE_TEST(counter == 1);

    /* Perform restricted ocall, expect ecall to fail */
    printf("%s(): OCALL(restricted)...\n", __FUNCTION__);
    res = oe_ocall(
        OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, OE_OCALL_FLAG_NOT_REENTRANT);
    printf(
        "%s(): OCALL returned. res=%x, ta->result=%x, counter=%x\n",
        __FUNCTION__,
        res,
        ta->result,
        counter);
    OE_TEST(res == OE_OK);
    OE_TEST(ta->result == OE_UNEXPECTED);
    OE_TEST(counter == 1);

    /* Perform regular ocall w/ ecall */
    res = oe_ocall(OE_FUNC_CALL_HOST, (uint64_t)cha, NULL, 0);
    OE_TEST(res == OE_OK);
    OE_TEST(ta->result == OE_OK);
    OE_TEST(counter == 2);

    ta->result = OE_OK;

    printf("%s(): Returning\n", __FUNCTION__);
}

OE_ECALL void ECallNested(void* args)
{
    OE_UNUSED(args);
    printf("%s(): Called, counter=%d\n", __FUNCTION__, counter);
    counter++;
    printf("%s(): Returning, counter=%d\n", __FUNCTION__, counter);
}
