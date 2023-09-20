.intel_syntax noprefix

# adopted from: https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
# ref: https://github.com/zoogie/bfCL/blob/master/cl/sha256_16.cl

#ifdef __APPLE__

#define _func(name) \
.global _##name ; \
_##name:

#else

#define _func(name) \
.global name ; \
name:

#endif

#define _xmm2sp(offset, regn) \
    movdqa  [rsp+16*offset], xmm##regn ;
#define _sp2xmm(regn, offset) \
    movdqa  xmm##regn, [rsp+16*offset] ;
#define _xmmldr(tmpr, reg, high, low) \
    mov     tmpr, low ; \
    movq    reg, tmpr ; \
    mov     tmpr, high ; \
    pinsrq  reg, tmpr, 1 ;
#define _xmmldr1(tmpr, reg, v) \
    mov     tmpr, v ; \
    movq    reg, tmpr ; \
    pinsrq  reg, tmpr, 1 ;

#define _shasr1(s0, s1, tmpr, regt, regk, msg, kh, kl) \
    _xmmldr (tmpr, regk, kh, kl) ; \
    movdqa  regt, msg ; \
    paddd   regt, regk ; \
    sha256rnds2 s1, s0, regt ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ;
#define _shasr2(s0, s1, tmpr, regt, regk, msg, pmsg, kh, kl) \
    _xmmldr (tmpr, regk, kh, kl) ; \
    movdqa  regt, msg ; \
    paddd   regt, regk ; \
    sha256rnds2 s1, s0, regt ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ; \
    sha256msg1  pmsg, msg ;
#define _shasr3(s0, s1, tmpr, regt, regk, msg, pmsg, nmsg, kh, kl) \
    _xmmldr (tmpr, regk, kh, kl) ; \
    movdqa  regt, msg ; \
    paddd   regt, regk ; \
    sha256rnds2 s1, s0, regt ; \
    movdqa  regk, msg ; \
    palignr regk, pmsg, 4 ; \
    paddd   nmsg, regk ; \
    sha256msg2  nmsg, msg ; \
    pshufd  regt, regt, 0xE ; \
    sha256rnds2 s0, s1, regt ; \
    sha256msg1  pmsg, msg ;


.text


# ---- volatile
#define RND     r9w
#define RND32   r9d

#define DAT0    xmm3
#define DAT12   xmm4
#define DAT3    xmm5

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
    # DAT12
    _xmmldr1(rax, DAT12, 0x0000000000000000)
    # DAT3
    movq    DAT3, rax
    mov     rax, 0x0000006000000000
    pinsrq  DAT3, rax, 1
    # RND
    mov     RND, 0x0
    # prepare new flag (need to be highest 16bit)
    rol     rdx, 48

refill_lfcs__mine_lfcs:
    # DAT0
    bswap   edi
    mov     rax, rdx
    or      rax, rdi # start_lfcs
    movq    DAT0, rax
    mov     rax, 0x8000000000000000
    pinsrq  DAT0, rax, 1

sha256_12_hashing__mine_lfcs:
    # --------------------------------
    # | ctual sha256_12 hashing
    # inject rnd into DAT0
    pinsrw  DAT0, RND32, 2

    # init state, pre shuffled
    _xmmldr (rax, STATE0, 0x6A09E667BB67AE85, 0x510E527F9B05688C)
    _xmmldr (rax, STATE1, 0x3C6EF372A54FF53A, 0x1F83D9AB5BE0CD19)

    # rounds 0-3
    movdqa  MSG0, DAT0
    _shasr1 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, 0xE9B5DBA5B5C0FBCF, 0x71374491428A2F98)

    # rounds 4-7
    movdqa  MSG1, DAT12
    _shasr2 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, 0xAB1C5ED5923F82A4, 0x59F111F13956C25B)

    # rounds 8-11
    movdqa  MSG2, DAT12
    _shasr2 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, 0x550C7DC3243185BE, 0x12835B01D807AA98)

    # rounds 12-15
    movdqa  MSG3, DAT3
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, 0xC19BF1749BDC06A7, 0x80DEB1FE72BE5D74)

    # rounds 16-19
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, 0x240CA1CC0FC19DC6, 0xEFBE4786E49B69C1)

    # rounds 20-23
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, 0x76F988DA5CB0A9DC, 0x4A7484AA2DE92C6F)

    # rounds 24-27
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, 0xBF597FC7B00327C8, 0xA831C66D983E5152)

    # rounds 28-31
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, 0x1429296706CA6351,  0xD5A79147C6E00BF3)

    # rounds 32-35
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, 0x53380D134D2C6DFC, 0x2E1B213827B70A85)

    # rounds 36-39
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, 0x92722C8581C2C92E, 0x766A0ABB650A7354)

    # rounds 40-43
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, 0xC76C51A3C24B8B70, 0xA81A664BA2BFE8A1)

    # rounds 44-47
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, MSG2, MSG0, 0x106AA070F40E3585, 0xD6990624D192E819)

    # rounds 48-51
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG0, MSG3, MSG1, 0x34B0BCB52748774C, 0x1E376C0819A4C116)

    # rounds 52-55
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG1, MSG0, MSG2, 0x682E6FF35B9CCA4F, 0x4ED8AA4A391C0CB3)

    # rounds 56-59
    _shasr3 (STATE0, STATE1, rax, xmm0, xmm1, MSG2, MSG1, MSG3, 0x8CC7020884C87814, 0x78A5636F748F82EE)

    # rounds 60-63
    _shasr1 (STATE0, STATE1, rax, xmm0, xmm1, MSG3, 0xC67178F2BEF9A3F7, 0xA4506CEB90BEFFFA)

    # combine state 
    _xmmldr (rax, xmm1, 0x3C6Ef372A54FF53A, 0x1F83D9AB5BE0CD19)
    paddd   STATE1, xmm1
    pshufd  xmm0, STATE0, 0x1B
    pshufd  STATE1, STATE1, 0xB1
    movdqa  STATE0, xmm0
    pblendw STATE0, STATE1, 0xF0
    palignr STATE1, xmm0, 8

    # result hash in high 64bit of STATE1 (swapped double dword)
    pextrq  rax, STATE1, 1

    cmp     rax, rcx
    jz      result_true__mine_lfcs

    inc     RND
    jnz     sha256_12_hashing__mine_lfcs

    bswap   edi
    inc     edi

    cmp     edi, esi
    jnz     refill_lfcs__mine_lfcs

result_false__mine_lfcs:
    mov     rax, 0 # false
    jmp     result_return__mine_lfcs

result_true__mine_lfcs:
    mov     rax, 1 # true

result_return__mine_lfcs:
    mov     rsi, 0
    #mov     si, RND
    mov     esi, RND32
    rol     rsi, 32
    bswap   edi
    or      rsi, rdi
    mov     [r8], rsi

    _sp2xmm(10, 0)
    _sp2xmm(11, 1)
    _sp2xmm(12, 2)
    _sp2xmm(13, 3)
    _sp2xmm(14, 4)
    _sp2xmm(15, 5)
    mov     rsp, rbp
    pop     rbp
    ret
