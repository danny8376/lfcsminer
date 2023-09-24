#ifdef __aarch64__
.arch armv8-a+sha2

# adopted from: https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
# ref: https://github.com/zoogie/bfCL/blob/master/cl/sha256_16.cl

#include "asm_common.h"


#define _V(n) v ## n
#define _Q(n) q ## n
#define V(n) _V(n)
#define Q(n) _Q(n)

#define _shasr1(s0, s1, tmpr, regt, nregt, regt2, msg, msg1, msg2, msg3, k) \
    sha256su0   _V(msg).4s, _V(msg1).4s ; \
    mov     _V(regt2).16b, _V(s0).16b ; \
    ldr     tmpr, =k ; \
    ld1     { _V(nregt).16b }, [tmpr] ; \
    add     _V(nregt).4s, _V(msg1).4s, _V(nregt).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ; \
    sha256su1   _V(msg).4s, _V(msg2).4s, _V(msg3).4s ;
#define _shasr2(s0, s1, tmpr, regt, nregt, regt2, msg, k) \
    mov     _V(regt2).16b, _V(s0).16b ; \
    ldr     tmpr, =k ; \
    ld1     { _V(nregt).16b }, [tmpr] ; \
    add     _V(nregt).4s, _V(msg).4s, _V(nregt).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ; \


.data


.align 8
    CD:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80

.align 16
    D1:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    D2:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    D3:  .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00

    I0:  .byte 0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB, 0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xF5, 0x4F, 0xA5
    I1:  .byte 0x7F, 0x52, 0x0E, 0x51, 0x8C, 0x68, 0x05, 0x9B, 0xAB, 0xD9, 0x83, 0x1F, 0x19, 0xCD, 0xE0, 0x5B

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


.text


# ---- volatile ----
#define RND     w9

#define DAT0    16

#define STATE0 26
#define STATE1 27

#define MSG0   28
#define MSG1   29
#define MSG2   30
#define MSG3   31

# ---- non-volatile ----

_func(mine_lfcs) # uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    mov     x10, x0
    mov     x11, x1
    mov     x12, x2
    mov     x13, x3
    mov     x14, x4
    # --------------------------------
    # | prepare data
    # RND
    mov     RND, #0x0
    # prepare new flag (need to be highest 16bit)
    lsl     x12, x12, #48

refill_lfcs__mine_lfcs:
    # DAT0
    rev     w10, w10
    orr     x0, x12, x10 // start_lfcs
    mov     V(DAT0).d[0], x0
    ldr     x0, =CD
    ld1     { V(DAT0).d }[1], [x0]

sha256_12_hashing__mine_lfcs:
    // --------------------------------
    // | ctual sha256_12 hashing
    // inject rnd into DAT0
    mov     V(DAT0).h[2], RND

    // init state, pre shuffled
    ldr     x0, =I0
    ld1     { V(STATE0).16b, V(STATE1).16b }, [x0]

    // init msg
    mov     V(MSG0).16b, V(DAT0).16b
    ldr     x0, =D1
    ld1     { V(MSG1).16b - V(MSG3).16b }, [x0]

    ldr     x0, =C0
    ld1     { v0.16b }, [x0]
    add     v0.4s, V(MSG0).4s, v0.4s

    // rounds 0-3
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG0, MSG1, MSG2, MSG3, C1)

    // rounds 4-7
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG1, MSG2, MSG3, MSG0, C2)

    // rounds 8-11
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG2, MSG3, MSG0, MSG1, C3)

    // rounds 12-15
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG3, MSG0, MSG1, MSG2, C4)

    // rounds 16-19
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG0, MSG1, MSG2, MSG3, C5)

    // rounds 20-23
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG1, MSG2, MSG3, MSG0, C6)

    // rounds 24-27
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG2, MSG3, MSG0, MSG1, C7)

    // rounds 28-31
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG3, MSG0, MSG1, MSG2, C8)

    // rounds 32-35
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG0, MSG1, MSG2, MSG3, C9)

    // rounds 36-39
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG1, MSG2, MSG3, MSG0, C10)

    // rounds 40-43
    _shasr1 (STATE0, STATE1, x0, 0, 1, 2, MSG2, MSG3, MSG0, MSG1, C11)

    // rounds 44-47
    _shasr1 (STATE0, STATE1, x0, 1, 0, 2, MSG3, MSG0, MSG1, MSG2, C12)

    // rounds 48-51
    _shasr2 (STATE0, STATE1, x0, 0, 1, 2, MSG1, C13)

    // rounds 52-55
    _shasr2 (STATE0, STATE1, x0, 1, 0, 2, MSG2, C14)

    // rounds 56-59
    _shasr2 (STATE0, STATE1, x0, 0, 1, 2, MSG3, C15)

    // rounds 60-63
    mov     v2.16b, V(STATE0).16b
    sha256h     Q(STATE0), Q(STATE1), v1.4s
    sha256h2    Q(STATE1), q2, v1.4s

    // combine state
    ldr     x0, =I1
    ld1     { v0.16b }, [x0]
    add     V(STATE1).4s, V(STATE1).4s, v0.4s

    // result hash in high 64bit of STATE1 (swapped double dword)
    mov     x0, V(STATE1).D[1]

    cmp     x0, x13
    beq     result_true__mine_lfcs

    add     RND, RND, #1
    cmp     RND, #0x10000
    bhs     next_lfcs__mine_lfcs
    b       sha256_12_hashing__mine_lfcs

next_lfcs__mine_lfcs:
    mov     RND, #0x0

    rev     w10, w10
    add     w10, w10, #1

    add     x15, x14, #32
    str     w10, [x15]
    add     x15, x14, #64
    str     w11, [x15]

    cmp     w10, w11
    bls     refill_lfcs__mine_lfcs

result_false__mine_lfcs:
    mov     x0, #0 // false
    b       result_return__mine_lfcs

result_true__mine_lfcs:
    mov     x0, #1 // true

result_return__mine_lfcs:
    mov     w1, RND
    lsl     x1, x1, #32
    rev     w10, w10
    orr     x1, x1, x10
    str     x1, [x14]

    ret

#endif
