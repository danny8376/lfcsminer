#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

// Include the GCC super header
#if defined(__GNUC__)
# include <x86intrin.h>
#endif

#if defined(_MSC_VER)

// Microsoft supports Intel SHA ACLE extensions as of Visual Studio 2015
# include <immintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT32 uint32_t;
typedef UINT8 uint8_t;

typedef LARGE_INTEGER TimeHP;
#define get_hp_time QueryPerformanceCounter

long long hp_time_diff(LARGE_INTEGER *pt0, LARGE_INTEGER *pt1) {
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	long long diff = pt1->QuadPart - pt0->QuadPart;
	diff *= 1000000;
	diff /= freq.QuadPart;
	return diff;
}

#else

#include <time.h>
typedef struct timespec TimeHP;

void get_hp_time(struct timespec *pt) {
	clock_gettime(CLOCK_MONOTONIC, pt);
}

long long hp_time_diff(struct timespec *pt0, struct timespec *pt1) {
	long long diff = pt1->tv_sec - pt0->tv_sec;
	diff *= 1000000;
	diff += (pt1->tv_nsec - pt0->tv_nsec) / 1000;
	return diff;
}

#endif

#define report_hash_rate(t0, t1) \
    printf("%.2f seconds, %.2f M/s\n", td / 1000000.0, tested * 1.0 / td);

#ifdef _WIN32
#ifdef __MINGW64__
#define LL "ll"
#else
#define LL "I64"
#endif
#else
#define LL "ll"
#endif


int is_supported_platform();

uint64_t mine_lfcs_x2(uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result);


int main(int argc, char **argv)
{
    uint32_t start = 0,
             end = 0;
    uint16_t newflag = 0;
    uint64_t target = 0,
             result = 0;

    TimeHP t0, t1;
    long long td = 0;

    if (!is_supported_platform()) {
        printf("this program require sha extension and sse4.1 support\n");
        return -3;
    }

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

    get_hp_time(&t0);

    if (!mine_lfcs_x2(start, end, newflag, target, &result)) {
        fprintf(stderr, "no hit\n");

        get_hp_time(&t1); td = hp_time_diff(&t0, &t1);
        printf("%.2f seconds, %.2f M/s\n", td / 1000000.0, (end - start) * 0x10000 * 1.0 / td);

        return 1;
    }

    get_hp_time(&t1); td = hp_time_diff(&t0, &t1);

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
        printf("%.2f seconds, %.2f M/s\n", td / 1000000.0, (end - start) * 0x10000 * 1.0 / td);
        return 0;
    }

    f = fopen("movable_part1.sed", "wb");
    if (f) {
        printf("movable_part1.sed not found, generating a new one...\n");
        fwrite(part1, 1, 0x1000, f);
        printf("don't you dare forget to add the id0 to it!\n");
        fclose(f);
        printf("%.2f seconds, %.2f M/s\n", td / 1000000.0, (end - start) * 0x10000 * 1.0 / td);
        return 0;
    }

    fprintf(stderr, "can't open movable_part1.sed to write\n");
    printf("%.2f seconds, %.2f M/s\n", td / 1000000.0, (end - start) * 0x10000 * 1.0 / td);
    return -2;
}
