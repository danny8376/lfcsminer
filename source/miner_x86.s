.intel_syntax noprefix

# adopted from: https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
# ref: https://github.com/zoogie/bfCL/blob/master/cl/sha256_16.cl

#ifdef __x86_64__

#include "asm_common_x86.h"


#define _xmmd(name) xmmword ptr [rip+name]
#define _qdat(name)   qword ptr [rip+name]
#define _ddat(name)   dword ptr [rip+name]

#define _xmm2sp(offset, regn) \
    movdqa  [rsp+16*offset], xmm##regn ;
#define _sp2xmm(regn, offset) \
    movdqa  xmm##regn, [rsp+16*offset] ;

#define _shasr1(s0, s1, tmpr, regt, msg, k) \
    movdqa  regt, msg ; \
    paddd   regt, _xmmd(k) ; \
    sha256rnds2 s1, s0, regt ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ;
#define _shasr2(s0, s1, tmpr, regt, msg, pmsg, k) \
    movdqa  regt, msg ; \
    paddd   regt, _xmmd(k) ; \
    sha256rnds2 s1, s0, regt ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ; \
    sha256msg1  pmsg, msg ;
#define _shasr3(s0, s1, tmpr, regt, regt2, msg, pmsg, nmsg, k) \
    movdqa  regt, msg ; \
    paddd   regt, _xmmd(k) ; \
    sha256rnds2 s1, s0, regt ; \
    movdqa  regt2, msg ; \
    palignr regt2, pmsg, 4 ; \
    paddd   nmsg, regt2 ; \
    sha256msg2  nmsg, msg ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ; \
    sha256msg1  pmsg, msg ;


.data


.align 8
    CD:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80

.align 16
    D12: .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    D3:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00

    I0:  .byte 0x8C, 0x68, 0x05, 0x9B, 0x7F, 0x52, 0x0E, 0x51, 0x85, 0xAE, 0x67, 0xBB, 0x67, 0xE6, 0x09, 0x6A
    I1:  .byte 0x19, 0xCD, 0xE0, 0x5B, 0xAB, 0xD9, 0x83, 0x1F, 0x3A, 0xF5, 0x4F, 0xA5, 0x72, 0xF3, 0x6E, 0x3C

    C0:  .byte 0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71, 0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9
    C1:  .byte 0x5B, 0xC2, 0x56, 0x39, 0xF1, 0x11, 0xF1, 0x59, 0xA4, 0x82, 0x3F, 0x92, 0xD5, 0x5E, 0x1C, 0xAB
    C2:  .byte 0x98, 0xAA, 0x07, 0xD8, 0x01, 0x5B, 0x83, 0x12, 0xBE, 0x85, 0x31, 0x24, 0xC3, 0x7D, 0x0C, 0x55
    C3:  .byte 0x74, 0x5D, 0xBE, 0x72, 0xFE, 0xB1, 0xDE, 0x80, 0xA7, 0x06, 0xDC, 0x9B, 0x74, 0xF1, 0x9B, 0xC1
    C4:  .byte 0xC1, 0x69, 0x9B, 0xE4, 0x86, 0x47, 0xBE, 0xEF, 0xC6, 0x9D, 0xC1, 0x0F, 0xCC, 0xA1, 0x0C, 0x24
    C5:  .byte 0x6F, 0x2C, 0xE9, 0x2D, 0xAA, 0x84, 0x74, 0x4A, 0xDC, 0xA9, 0xB0, 0x5C, 0xDA, 0x88, 0xF9, 0x76
    C6:  .byte 0x52, 0x51, 0x3E, 0x98, 0x6D, 0xC6, 0x31, 0xA8, 0xC8, 0x27, 0x03, 0xB0, 0xC7, 0x7F, 0x59, 0xBF
    C7:  .byte 0xF3, 0x0B, 0xE0, 0xC6, 0x47, 0x91, 0xA7, 0xD5, 0x51, 0x63, 0xCA, 0x06, 0x67, 0x29, 0x29, 0x14
    C8:  .byte 0x85, 0x0A, 0xB7, 0x27, 0x38, 0x21, 0x1B, 0x2E, 0xFC, 0x6D, 0x2C, 0x4D, 0x13, 0x0D, 0x38, 0x53
    C9:  .byte 0x54, 0x73, 0x0A, 0x65, 0xBB, 0x0A, 0x6A, 0x76, 0x2E, 0xC9, 0xC2, 0x81, 0x85, 0x2C, 0x72, 0x92
    C10: .byte 0xA1, 0xE8, 0xBF, 0xA2, 0x4B, 0x66, 0x1A, 0xA8, 0x70, 0x8B, 0x4B, 0xC2, 0xA3, 0x51, 0x6C, 0xC7
    C11: .byte 0x19, 0xE8, 0x92, 0xD1, 0x24, 0x06, 0x99, 0xD6, 0x85, 0x35, 0x0E, 0xF4, 0x70, 0xA0, 0x6A, 0x10
    C12: .byte 0x16, 0xC1, 0xA4, 0x19, 0x08, 0x6C, 0x37, 0x1E, 0x4C, 0x77, 0x48, 0x27, 0xB5, 0xBC, 0xB0, 0x34
    C13: .byte 0xB3, 0x0C, 0x1C, 0x39, 0x4A, 0xAA, 0xD8, 0x4E, 0x4F, 0xCA, 0x9C, 0x5B, 0xF3, 0x6F, 0x2E, 0x68
    C14: .byte 0xEE, 0x82, 0x8F, 0x74, 0x6F, 0x63, 0xA5, 0x78, 0x14, 0x78, 0xC8, 0x84, 0x08, 0x02, 0xC7, 0x8C
    C15: .byte 0xFA, 0xFF, 0xBE, 0x90, 0xEB, 0x6C, 0x50, 0xA4, 0xF7, 0xA3, 0xF9, 0xBE, 0xF2, 0x78, 0x71, 0xC6

    S:   .byte 0x19, 0xCD, 0xE0, 0x5B, 0xAB, 0xD9, 0x83, 0x1F, 0x3A, 0xF5, 0x4F, 0xA5, 0x72, 0xf3, 0x6E, 0x3C


.text


# ---- volatile ----
#define RND     r10w
#define RND32   r10d

#define DAT0    xmm3

# ---- non-volatile ----
#define STATE0  xmm10
#define STATE1  xmm11

#define MSG0    xmm12
#define MSG1    xmm13
#define MSG2    xmm14
#define MSG3    xmm15

_func(mine_lfcs) # uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    push    rbp
    mov     rbp, rsp
    # store xmm10-15 x6
    lea     rsp, [rsp-16*6]
    _xmm2sp(0, 10)
    _xmm2sp(1, 11)
    _xmm2sp(2, 12)
    _xmm2sp(3, 13)
    _xmm2sp(4, 14)
    _xmm2sp(5, 15)
    # --------------------------------
    # | prepare data
    # RND
    mov     RND, 0x0
    # prepare new flag (need to be highest 16bit)
    rol     rp3, 48

refill_lfcs__mine_lfcs:
    # DAT0
    bswap   ep1
    mov     rax, rp3
    or      rax, rp1 # start_lfcs
    movq    DAT0, rax
    pinsrq  DAT0, _qdat(CD), 1

sha256_12_hashing__mine_lfcs:
    # --------------------------------
    # | ctual sha256_12 hashing
    # inject rnd into DAT0
    pinsrw  DAT0, RND32, 2

    # init state, pre shuffled
    movdqa  STATE0, _xmmd(I0)
    movdqa  STATE1, _xmmd(I1)

    # rounds 0-3
    movdqa  MSG0, DAT0
    _shasr1 (STATE0, STATE1, rax, xmm0, MSG0, C0)

    # rounds 4-7
    movdqa  MSG1, _xmmd(D12)
    _shasr2 (STATE0, STATE1, rax, xmm0, MSG1, MSG0, C1)

    # rounds 8-11
    movdqa  MSG2, _xmmd(D12)
    _shasr2 (STATE0, STATE1, rax, xmm0, MSG2, MSG1, C2)

    # rounds 12-15
    movdqa  MSG3, _xmmd(D3)
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, C3)

    # rounds 16-19
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, C4)

    # rounds 20-23
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, C5)

    # rounds 24-27
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, C6)

    # rounds 28-31
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, C7)

    # rounds 32-35
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, C8)

    # rounds 36-39
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, C9)

    # rounds 40-43
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, C10)

    # rounds 44-47
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, C11)

    # rounds 48-51
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, C12)

    # rounds 52-55
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, C13)

    # rounds 56-59
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, C14)

    # rounds 60-63
    _shasr1 (STATE0, STATE1, rax, xmm0, MSG3, C15)

    # combine state 
    paddd   STATE1, _xmmd(S)
    pshufd  xmm0, STATE0, 0x1B
    pshufd  STATE1, STATE1, 0xB1
    movdqa  STATE0, xmm0
    pblendw STATE0, STATE1, 0xF0
    palignr STATE1, xmm0, 8

    # result hash in high 64bit of STATE1 (swapped double dword)
    pextrq  rax, STATE1, 1

    cmp     rax, rp4
    jz      result_true__mine_lfcs

    inc     RND
    jnz     sha256_12_hashing__mine_lfcs

    bswap   ep1
    inc     ep1

    cmp     ep1, ep2
    jle     refill_lfcs__mine_lfcs

result_false__mine_lfcs:
    mov     rax, 0 # false
    jmp     result_return__mine_lfcs

result_true__mine_lfcs:
    mov     rax, 1 # true

result_return__mine_lfcs:
    mov     rp2, 0
    #mov     p2, RND
    mov     ep2, RND32
    rol     rp2, 32
    bswap   ep1
    or      rp2, rp1
    mov     p5ptr, rp2

    _sp2xmm(10, 0)
    _sp2xmm(11, 1)
    _sp2xmm(12, 2)
    _sp2xmm(13, 3)
    _sp2xmm(14, 4)
    _sp2xmm(15, 5)
    mov     rsp, rbp
    pop     rbp
    ret

#endif
