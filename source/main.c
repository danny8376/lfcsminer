#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

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


uint64_t mine_lfcs(uint32_t start_lfcs, uint32_t end_lfcs, uint64_t target_hash, uint64_t *result);


int main(int argc, char **argv)
{
    uint32_t start = 0,
             end = 0;
    uint64_t target = 0,
             result = 0;
    int ret = 1;

    if(argc!=4){
        #ifdef _WIN32
        printf("lfcsminer <start_lfcs> <end_lfcs> <target_hash>\nNote that all values interpreted as hex\n");
        #else
        printf("./lfcsminer <start_lfcs> <end_lfcs> <target_hash>\nNote that all values interpreted as hex\n");
        #endif
        return 1;
    }

    start = strtoul(argv[1], NULL, 16);
    end = strtoul(argv[2], NULL, 16);

    target = strtoull(argv[3], NULL, 16);
    target = (target << 32) | (target >> 32);

    if (mine_lfcs(start, end, target, &result)) {
        ret = 0;
        printf("got a hit: 0x%08x (rnd: 0x%04x)\n", (uint32_t)(result & 0xFFFFFFFF), (uint16_t)(result >> 32));
    }

    return ret;
}
