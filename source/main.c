#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

// Include the GCC super header
#if defined(__GNUC__)
# include <x86intrin.h>
#endif

// Microsoft supports Intel SHA ACLE extensions as of Visual Studio 2015
#if defined(_MSC_VER)
# include <immintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT32 uint32_t;
typedef UINT8 uint8_t;
#endif

#ifdef _WIN32
#define LL "I64"
#else
#define LL "ll"
#endif


uint64_t mine_lfcs(uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result);


int main(int argc, char **argv)
{
    uint32_t start = 0,
             end = 0;
    uint16_t newflag = 0;
    uint64_t target = 0,
             result = 0;

    if(argc!=5){
        #ifdef _WIN32
        printf("lfcsminer <start_lfcs> <end_lfcs> <new_flag> <target_hash>\nNote that all values interpreted as hex\n");
        #else
        printf("./lfcsminer <start_lfcs> <end_lfcs> <new_flag> <target_hash>\nNote that all values interpreted as hex\n");
        #endif
        return -1;
    }

    start = strtoul(argv[1], NULL, 16);
    end = strtoul(argv[2], NULL, 16);

    newflag = strtoul(argv[3], NULL, 16);

    target = strtoull(argv[4], NULL, 16);
    target = (target << 32) | (target >> 32);

    if (!mine_lfcs(start, end, newflag, target, &result)) {
        fprintf(stderr, "no hit\n");
        return 1;
    }

    uint32_t lfcs = result & 0xFFFFFFFF;
    uint16_t rnd = result >> 32;
    printf("got a hit: 0x%08x (rnd: 0x%04x)\n", lfcs, rnd);

    uint8_t part1[0x1000] = {0};
    memcpy(part1, &lfcs, 4);
    memcpy(part1+4, &newflag, 2);
    FILE *f = fopen("movable_part1.sed", "rb+");
    if (f) {
        printf("existing movable_part1.sed found, adding lfcs...\n");
        fwrite(part1, 1, 8, f);
        fclose(f);
        return 0;
    }

    f = fopen("movable_part1.sed", "wb");
    if (f) {
        printf("movable_part1.sed not found, generating a new one...\n");
        fwrite(part1, 1, 0x1000, f);
        printf("don't you dare forget to add the id0 to it!\n");
        fclose(f);
        return 0;
    }

    fprintf(stderr, "can't open movable_part1.sed to write\n");
    return -2;
}
