#ifdef __x86_64__

void get_cpu_id(int pa, int pc, int *ra, int *rb, int *rc, int *rd) {
    int a, b, c, d;

    asm volatile ("cpuid"
        :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
        :"a"(pa), "c"(pc)
    );

    if (ra) *ra = a;
    if (rb) *rb = b;
    if (rc) *rc = c;
    if (rd) *rd = d;
}

int is_supported_platform() {
    int cpu_id, sha, sse41;
    get_cpu_id(7, 0, 0, &cpu_id, 0, 0);
    sha = (cpu_id >> 29) & 1;
    get_cpu_id(1, 0, 0, 0, &cpu_id, 0);
    sse41 = (cpu_id >> 19) & 1;
    return sha && sse41;
}

#elif __aarch64__

int is_supported_platform() {
    // lazy for now
    return 1;
}

#endif
