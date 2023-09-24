#include "asm_common.h"

#define _func __func

#ifdef _WIN32

#define rp1 rcx
#define rp2 rdx
#define rp3 r8
#define rp4 r9

#define ep1 ecx
#define ep2 edx
#define ep3 r8d
#define ep4 r9d

#define p1 cx
#define p2 dx
#define p3 r8w
#define p4 r9w

#define p5ptr [rbp+0x48]

#else

#define rp1 rdi
#define rp2 rsi
#define rp3 rdx
#define rp4 rcx

#define ep1 edi
#define ep2 esi
#define ep3 edx
#define ep4 ecx

#define p1 di
#define p2 si
#define p3 dx
#define p4 cx

#define p5ptr [r8]

#endif
