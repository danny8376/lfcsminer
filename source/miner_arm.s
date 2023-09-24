#ifdef __aarch64__
.arch armv8-a+sha2

# adopted from: https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
# ref: https://github.com/zoogie/bfCL/blob/master/cl/sha256_16.cl

#include "asm_common_arm.h"


#define _V(n) v ## n
#define _Q(n) q ## n
#define V(n) _V(n)
#define Q(n) _Q(n)

#define _vldrk(tmpr, reg, k) \
    ldr     tmpr, =k ; \
    ld1     { _V(reg).16b }, [tmpr] ;

#define _shasr1(s0, s1, tmpr, regt, nregt, regt2, msg, msg1, msg2, msg3, k) \
    sha256su0   _V(msg).4s, _V(msg1).4s ; \
    mov     _V(regt2).16b, _V(s0).16b ; \
    _vldrk  (tmpr, nregt, k) ; \
    add     _V(nregt).4s, _V(msg1).4s, _V(nregt).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ; \
    sha256su1   _V(msg).4s, _V(msg2).4s, _V(msg3).4s ;
#define _shasr2(s0, s1, tmpr, regt, nregt, regt2, msg, k) \
    mov     _V(regt2).16b, _V(s0).16b ; \
    _vldrk  (tmpr, nregt, k) ; \
    add     _V(nregt).4s, _V(msg).4s, _V(nregt).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ;

#define _shasr1r(s0, s1, regt, nregt, regt2, msg, msg1, msg2, msg3, k) \
    sha256su0   _V(msg).4s, _V(msg1).4s ; \
    mov     _V(regt2).16b, _V(s0).16b ; \
    add     _V(nregt).4s, _V(msg1).4s, _V(k).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ; \
    sha256su1   _V(msg).4s, _V(msg2).4s, _V(msg3).4s ;
#define _shasr2r(s0, s1, regt, nregt, regt2, msg, k) \
    mov     _V(regt2).16b, _V(s0).16b ; \
    add     _V(nregt).4s, _V(msg).4s, _V(k).4s ; \
    sha256h     _Q(s0), _Q(s1), _V(regt).4s ; \
    sha256h2    _Q(s1), _Q(regt2), _V(regt).4s ;


.text


// ---- volatile ----
#define RND     w9

#define DAT0    16

#define TMP0    24
#define TMP1    25

#define STATE0  26
#define STATE1  27

#define MSG0    28
#define MSG1    29
#define MSG2    30
#define MSG3    31

// ---- non-volatile ----

_func(mine_lfcs) // uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    mov     x10, x0
    mov     x11, x1
    mov     x12, x2
    mov     x13, x3
    mov     x14, x4

    // --------------------------------
    // | prepare data
    // RND
    mov     RND, #0x0
    // prepare new flag (need to be highest 16bit)
    lsl     x12, x12, #48

refill_lfcs__mine_lfcs:
    // DAT0
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
    add     V(TMP0).4s, V(MSG0).4s, v0.4s

    // rounds 0-3
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, C1)

    // rounds 4-7
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, C2)

    // rounds 8-11
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, C3)

    // rounds 12-15
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, C4)

    // rounds 16-19
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, C5)

    // rounds 20-23
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, C6)

    // rounds 24-27
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, C7)

    // rounds 28-31
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, C8)

    // rounds 32-35
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, C9)

    // rounds 36-39
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, C10)

    // rounds 40-43
    _shasr1 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, C11)

    // rounds 44-47
    _shasr1 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, C12)

    // rounds 48-51
    _shasr2 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG1, C13)

    // rounds 52-55
    _shasr2 (STATE0, STATE1, x0, TMP1, TMP0, 0, MSG2, C14)

    // rounds 56-59
    _shasr2 (STATE0, STATE1, x0, TMP0, TMP1, 0, MSG3, C15)

    // rounds 60-63
    mov     v0.16b, V(STATE0).16b
    sha256h     Q(STATE0), Q(STATE1), V(TMP1).4s
    sha256h2    Q(STATE1), q0, V(TMP1).4s

    // combine state
    ldr     x0, =I1
    ld1     { v0.16b }, [x0]
    add     V(STATE1).4s, V(STATE1).4s, v0.4s

    // result hash in high 64bit of STATE1 (swapped double dword)
    mov     x0, V(STATE1).d[1]

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


// ---- volatile ----
//      RND     w9

//      DAT0    16

//      TMP0    24
//      TMP1    25

//      STATE0  26
//      STATE1  27

//      MSG0    28
//      MSG1    29
//      MSG2    30
//      MSG3    31

#define TMP0X   6
#define TMP1X   7

#define STATE0X 18
#define STATE1X 19

#define MSG0X   20
#define MSG1X   21
#define MSG2X   22
#define MSG3X   23

// ---- non-volatile ----

_func(mine_lfcs_x2) // uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    mov     x10, x0
    mov     x11, x1
    mov     x12, x2
    mov     x13, x3
    mov     x14, x4

    // --------------------------------
    // | prepare data
    // RND
    mov     RND, #0x0
    // prepare new flag (need to be highest 16bit)
    lsl     x12, x12, #48

refill_lfcs__mine_lfcs_x2:
    // DAT0
    rev     w10, w10
    orr     x0, x12, x10 // start_lfcs
    mov     V(DAT0).d[0], x0
    ldr     x0, =CD
    ld1     { V(DAT0).d }[1], [x0]

sha256_12_hashing__mine_lfcs_x2:
    // --------------------------------
    // | ctual sha256_12 hashing
    // init state, pre shuffled
    ldr     x0, =I0
    ld1     { V(STATE0).16b, V(STATE1).16b }, [x0]
    ld1     { V(STATE0X).16b, V(STATE1X).16b }, [x0]

    // init msg
    mov     V(MSG0).16b, V(DAT0).16b
    mov     V(MSG0).h[2], RND

    add     RND, RND, #1
    mov     V(MSG0X).16b, V(DAT0).16b
    mov     V(MSG0X).h[2], RND

    ldr     x0, =D1
    ld1     { V(MSG1).16b - V(MSG3).16b }, [x0]
    ld1     { V(MSG1X).16b - V(MSG3X).16b }, [x0]

    ldr     x0, =C0
    ld1     { v0.16b }, [x0]
    add     V(TMP0).4s, V(MSG0).4s, v0.4s
    add     V(TMP0X).4s, V(MSG0X).4s, v0.4s

    // rounds 0-3
    _vldrk(x0, 1, C1)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)

    // rounds 4-7
    _vldrk(x0, 1, C2)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)

    // rounds 8-11
    _vldrk(x0, 1, C3)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)

    // rounds 12-15
    _vldrk(x0, 1, C4)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)

    // rounds 16-19
    _vldrk(x0, 1, C5)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)

    // rounds 20-23
    _vldrk(x0, 1, C6)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)

    // rounds 24-27
    _vldrk(x0, 1, C7)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)

    // rounds 28-31
    _vldrk(x0, 1, C8)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)

    // rounds 32-35
    _vldrk(x0, 1, C9)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)

    // rounds 36-39
    _vldrk(x0, 1, C10)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)

    // rounds 40-43
    _vldrk(x0, 1, C11)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)

    // rounds 44-47
    _vldrk(x0, 1, C12)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)

    // rounds 48-51
    _vldrk(x0, 1, C13)
    _shasr2r(STATE0, STATE1, TMP0, TMP1, 0, MSG1, 1)
    _shasr2r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG1X, 1)

    // rounds 52-55
    _vldrk(x0, 1, C14)
    _shasr2r(STATE0, STATE1, TMP1, TMP0, 0, MSG2, 1)
    _shasr2r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG2X, 1)

    // rounds 56-59
    _vldrk(x0, 1, C15)
    _shasr2r(STATE0, STATE1, TMP0, TMP1, 0, MSG3, 1)
    _shasr2r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG3X, 1)

    // rounds 60-63
    mov     v0.16b, V(STATE0).16b
    sha256h     Q(STATE0), Q(STATE1), V(TMP1).4s
    sha256h2    Q(STATE1), q0, V(TMP1).4s

    mov     v0.16b, V(STATE0X).16b
    sha256h     Q(STATE0X), Q(STATE1X), V(TMP1X).4s
    sha256h2    Q(STATE1X), q0, V(TMP1X).4s

    // combine state
    ldr     x0, =I1
    ld1     { v0.16b }, [x0]
    add     V(STATE1).4s, V(STATE1).4s, v0.4s

    add     V(STATE1X).4s, V(STATE1X).4s, v0.4s

    // result hash in high 64bit of STATE1 (swapped double dword)
    mov     x0, V(STATE1).d[1]
    mov     x1, V(STATE1X).d[1]

    cmp     x0, x13
    beq     result_true_rnd0__mine_lfcs_x2

    cmp     x1, x13
    beq     result_true_rnd1__mine_lfcs_x2

    add     RND, RND, #1
    cmp     RND, #0x10000
    bhs     next_lfcs__mine_lfcs_x2
    b       sha256_12_hashing__mine_lfcs_x2

next_lfcs__mine_lfcs_x2:
    mov     RND, #0x0

    rev     w10, w10
    add     w10, w10, #1

    cmp     w10, w11
    bls     refill_lfcs__mine_lfcs_x2

result_false__mine_lfcs_x2:
    mov     x0, #0 // false
    b       result_return__mine_lfcs_x2

result_true_rnd0__mine_lfcs_x2:
    sub     RND, RND, #1

result_true_rnd1__mine_lfcs_x2:
    mov     x0, #1 // true

result_return__mine_lfcs_x2:
    mov     w1, RND
    lsl     x1, x1, #32
    rev     w10, w10
    orr     x1, x1, x10
    str     x1, [x14]

    ret


// ---- volatile ----
//      RND     w9

#define DAT0Y   9

//      TMP0    24
//      TMP1    25

//      STATE0  26
//      STATE1  27

//      MSG0    28
//      MSG1    29
//      MSG2    30
//      MSG3    31

//      TMP0X   6
//      TMP1X   7

//      STATE0X 18
//      STATE1X 19

//      MSG0X   20
//      MSG1X   21
//      MSG2X   22
//      MSG3X   23

#define TMP0Y   10
#define TMP1Y   11

#define STATE0Y 12
#define STATE1Y 13

#define MSG0Y   14
#define MSG1Y   15
#define MSG2Y   16
#define MSG3Y   17

// ---- non-volatile ----

_func(mine_lfcs_x3) // uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    sub     sp, sp, #32
    st1     { v8.1d - v11.1d }, [sp]
    sub     sp, sp, #32
    st1     { v12.1d - v15.1d }, [sp]
    mov     x10, x0
    mov     x11, x1
    mov     x12, x2
    mov     x13, x3
    mov     x14, x4

    // --------------------------------
    // | prepare data
    // RND
    mov     RND, #0x0
    // prepare new flag (need to be highest 16bit)
    lsl     x12, x12, #48

refill_lfcs__mine_lfcs_x3:
    // DAT0
    rev     w10, w10
    orr     x0, x12, x10 // start_lfcs
    mov     V(DAT0Y).d[0], x0
    ldr     x0, =CD
    ld1     { V(DAT0Y).d }[1], [x0]

sha256_12_hashing__mine_lfcs_x3:
    // --------------------------------
    // | ctual sha256_12 hashing
    // init state, pre shuffled
    ldr     x0, =I0
    ld1     { V(STATE0).16b, V(STATE1).16b }, [x0]
    ld1     { V(STATE0X).16b, V(STATE1X).16b }, [x0]
    ld1     { V(STATE0Y).16b, V(STATE1Y).16b }, [x0]

    // init msg
    mov     V(MSG0).16b, V(DAT0Y).16b
    mov     V(MSG0).h[2], RND

    add     RND, RND, #1
    mov     V(MSG0X).16b, V(DAT0Y).16b
    mov     V(MSG0X).h[2], RND

    add     RND, RND, #1
    mov     V(MSG0Y).16b, V(DAT0Y).16b
    mov     V(MSG0Y).h[2], RND

    ldr     x0, =D1
    ld1     { V(MSG1).16b - V(MSG3).16b }, [x0]
    ld1     { V(MSG1X).16b - V(MSG3X).16b }, [x0]
    ld1     { V(MSG1Y).16b - V(MSG3Y).16b }, [x0]

    ldr     x0, =C0
    ld1     { v0.16b }, [x0]
    add     V(TMP0).4s, V(MSG0).4s, v0.4s
    add     V(TMP0X).4s, V(MSG0X).4s, v0.4s
    add     V(TMP0Y).4s, V(MSG0Y).4s, v0.4s

    // rounds 0-3
    _vldrk(x0, 1, C1)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG0Y, MSG1Y, MSG2Y, MSG3Y, 1)

    // rounds 4-7
    _vldrk(x0, 1, C2)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG1Y, MSG2Y, MSG3Y, MSG0Y, 1)

    // rounds 8-11
    _vldrk(x0, 1, C3)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG2Y, MSG3Y, MSG0Y, MSG1Y, 1)

    // rounds 12-15
    _vldrk(x0, 1, C4)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG3Y, MSG0Y, MSG1Y, MSG2Y, 1)

    // rounds 16-19
    _vldrk(x0, 1, C5)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG0Y, MSG1Y, MSG2Y, MSG3Y, 1)

    // rounds 20-23
    _vldrk(x0, 1, C6)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG1Y, MSG2Y, MSG3Y, MSG0Y, 1)

    // rounds 24-27
    _vldrk(x0, 1, C7)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG2Y, MSG3Y, MSG0Y, MSG1Y, 1)

    // rounds 28-31
    _vldrk(x0, 1, C8)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG3Y, MSG0Y, MSG1Y, MSG2Y, 1)

    // rounds 32-35
    _vldrk(x0, 1, C9)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG0, MSG1, MSG2, MSG3, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG0X, MSG1X, MSG2X, MSG3X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG0Y, MSG1Y, MSG2Y, MSG3Y, 1)

    // rounds 36-39
    _vldrk(x0, 1, C10)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG1, MSG2, MSG3, MSG0, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG1X, MSG2X, MSG3X, MSG0X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG1Y, MSG2Y, MSG3Y, MSG0Y, 1)

    // rounds 40-43
    _vldrk(x0, 1, C11)
    _shasr1r(STATE0, STATE1, TMP0, TMP1, 0, MSG2, MSG3, MSG0, MSG1, 1)
    _shasr1r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG2X, MSG3X, MSG0X, MSG1X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG2Y, MSG3Y, MSG0Y, MSG1Y, 1)

    // rounds 44-47
    _vldrk(x0, 1, C12)
    _shasr1r(STATE0, STATE1, TMP1, TMP0, 0, MSG3, MSG0, MSG1, MSG2, 1)
    _shasr1r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG3X, MSG0X, MSG1X, MSG2X, 1)
    _shasr1r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG3Y, MSG0Y, MSG1Y, MSG2Y, 1)

    // rounds 48-51
    _vldrk(x0, 1, C13)
    _shasr2r(STATE0, STATE1, TMP0, TMP1, 0, MSG1, 1)
    _shasr2r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG1X, 1)
    _shasr2r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG1Y, 1)

    // rounds 52-55
    _vldrk(x0, 1, C14)
    _shasr2r(STATE0, STATE1, TMP1, TMP0, 0, MSG2, 1)
    _shasr2r(STATE0X, STATE1X, TMP1X, TMP0X, 0, MSG2X, 1)
    _shasr2r(STATE0Y, STATE1Y, TMP1Y, TMP0Y, 0, MSG2Y, 1)

    // rounds 56-59
    _vldrk(x0, 1, C15)
    _shasr2r(STATE0, STATE1, TMP0, TMP1, 0, MSG3, 1)
    _shasr2r(STATE0X, STATE1X, TMP0X, TMP1X, 0, MSG3X, 1)
    _shasr2r(STATE0Y, STATE1Y, TMP0Y, TMP1Y, 0, MSG3Y, 1)

    // rounds 60-63
    mov     v0.16b, V(STATE0).16b
    sha256h     Q(STATE0), Q(STATE1), V(TMP1).4s
    sha256h2    Q(STATE1), q0, V(TMP1).4s

    mov     v0.16b, V(STATE0X).16b
    sha256h     Q(STATE0X), Q(STATE1X), V(TMP1X).4s
    sha256h2    Q(STATE1X), q0, V(TMP1X).4s

    mov     v0.16b, V(STATE0Y).16b
    sha256h     Q(STATE0Y), Q(STATE1Y), V(TMP1Y).4s
    sha256h2    Q(STATE1Y), q0, V(TMP1Y).4s

    // combine state
    ldr     x0, =I1
    ld1     { v0.16b }, [x0]
    add     V(STATE1).4s, V(STATE1).4s, v0.4s
    add     V(STATE1X).4s, V(STATE1X).4s, v0.4s
    add     V(STATE1Y).4s, V(STATE1Y).4s, v0.4s

    // result hash in high 64bit of STATE1 (swapped double dword)
    mov     x0, V(STATE1).d[1]
    mov     x1, V(STATE1X).d[1]
    mov     x2, V(STATE1Y).d[1]

    cmp     x0, x13
    beq     result_true_rnd0__mine_lfcs_x3

    cmp     x1, x13
    beq     result_true_rnd1__mine_lfcs_x3

    cmp     x2, x13
    beq     result_true_rnd2__mine_lfcs_x3

    add     RND, RND, #1
    cmp     RND, #0x10000
    bhs     next_lfcs__mine_lfcs_x3
    b       sha256_12_hashing__mine_lfcs_x3

next_lfcs__mine_lfcs_x3:
    mov     RND, #0x0

    rev     w10, w10
    add     w10, w10, #1

    cmp     w10, w11
    bls     refill_lfcs__mine_lfcs_x3

result_false__mine_lfcs_x3:
    mov     x0, #0 // false
    b       result_return__mine_lfcs_x3

result_true_rnd0__mine_lfcs_x3:
    sub     RND, RND, #1

result_true_rnd1__mine_lfcs_x3:
    sub     RND, RND, #1

result_true_rnd2__mine_lfcs_x3:
    mov     x0, #1 // true

result_return__mine_lfcs_x3:
    mov     w1, RND
    lsl     x1, x1, #32
    rev     w10, w10
    orr     x1, x1, x10
    str     x1, [x14]

    ld1     { v8.1d - v11.1d }, [sp], #32
    ld1     { v12.1d - v15.1d }, [sp], #32
    ret


// ---- volatile ----
//      RRND     w9

#define RDAT0    7

// ---- non-volatile ----
#define RTMP0    8
#define RTMP1    9

#define RSTATE0  10
#define RSTATE1  11

#define RMSG0    12
#define RMSG1    13
#define RMSG2    14
#define RMSG3    15

_func(mine_lfcs_rk) // uint32_t start_lfcs, uint32_t end_lfcs, uint16_t new_flag, uint64_t target_hash, uint64_t *result
    sub     sp, sp, #32
    st1     { v8.1d - v11.1d }, [sp]
    sub     sp, sp, #32
    st1     { v12.1d - v15.1d }, [sp]
    mov     x10, x0
    mov     x11, x1
    mov     x12, x2
    mov     x13, x3
    mov     x14, x4

    ldr     x0, =C0
    ld1     { v16.16b - v19.16b }, [x0], #64
    ld1     { v20.16b - v23.16b }, [x0], #64
    ld1     { v24.16b - v27.16b }, [x0], #64
    ld1     { v28.16b - v31.16b }, [x0], #64
    // --------------------------------
    // | prepare data
    // RND
    mov     RND, #0x0
    // prepare new flag (need to be highest 16bit)
    lsl     x12, x12, #48

refill_lfcs__mine_lfcs_rk:
    // RDAT0
    rev     w10, w10
    orr     x0, x12, x10 // start_lfcs
    mov     V(RDAT0).d[0], x0
    ldr     x0, =CD
    ld1     { V(RDAT0).d }[1], [x0]

sha256_12_hashing__mine_lfcs_rk:
    // --------------------------------
    // | ctual sha256_12 hashing
    // inject rnd into RDAT0
    mov     V(RDAT0).h[2], RND

    // init state, pre shuffled
    ldr     x0, =I0
    ld1     { V(RSTATE0).16b, V(RSTATE1).16b }, [x0]

    // init msg
    mov     V(RMSG0).16b, V(RDAT0).16b
    ldr     x0, =D1
    ld1     { V(RMSG1).16b - V(RMSG3).16b }, [x0]

    add     V(RTMP0).4s, V(RMSG0).4s, v16.4s

    // rounds 0-3
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG0, RMSG1, RMSG2, RMSG3, 17)

    // rounds 4-7
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG1, RMSG2, RMSG3, RMSG0, 18)

    // rounds 8-11
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG2, RMSG3, RMSG0, RMSG1, 19)

    // rounds 12-15
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG3, RMSG0, RMSG1, RMSG2, 20)

    // rounds 16-19
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG0, RMSG1, RMSG2, RMSG3, 21)

    // rounds 20-23
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG1, RMSG2, RMSG3, RMSG0, 22)

    // rounds 24-27
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG2, RMSG3, RMSG0, RMSG1, 23)

    // rounds 28-31
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG3, RMSG0, RMSG1, RMSG2, 24)

    // rounds 32-35
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG0, RMSG1, RMSG2, RMSG3, 25)

    // rounds 36-39
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG1, RMSG2, RMSG3, RMSG0, 26)

    // rounds 40-43
    _shasr1r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG2, RMSG3, RMSG0, RMSG1, 27)

    // rounds 44-47
    _shasr1r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG3, RMSG0, RMSG1, RMSG2, 28)

    // rounds 48-51
    _shasr2r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG1, 29)

    // rounds 52-55
    _shasr2r(RSTATE0, RSTATE1, RTMP1, RTMP0, 0, RMSG2, 30)

    // rounds 56-59
    _shasr2r(RSTATE0, RSTATE1, RTMP0, RTMP1, 0, RMSG3, 31)

    // rounds 60-63
    mov     v0.16b, V(RSTATE0).16b
    sha256h     Q(RSTATE0), Q(RSTATE1), V(RTMP1).4s
    sha256h2    Q(RSTATE1), q0, V(RTMP1).4s

    // combine state
    ldr     x0, =I1
    ld1     { v0.16b }, [x0]
    add     V(RSTATE1).4s, V(RSTATE1).4s, v0.4s

    // result hash in high 64bit of RSTATE1 (swapped double dword)
    mov     x0, V(RSTATE1).d[1]

    cmp     x0, x13
    beq     result_true__mine_lfcs_rk

    add     RND, RND, #1
    cmp     RND, #0x10000
    bhs     next_lfcs__mine_lfcs_rk
    b       sha256_12_hashing__mine_lfcs_rk

next_lfcs__mine_lfcs_rk:
    mov     RND, #0x0

    rev     w10, w10
    add     w10, w10, #1

    cmp     w10, w11
    bls     refill_lfcs__mine_lfcs_rk

result_false__mine_lfcs_rk:
    mov     x0, #0 // false
    b       result_return__mine_lfcs_rk

result_true__mine_lfcs_rk:
    mov     x0, #1 // true

result_return__mine_lfcs_rk:
    mov     w1, RND
    lsl     x1, x1, #32
    rev     w10, w10
    orr     x1, x1, x10
    str     x1, [x14]

    ld1     { v8.1d - v11.1d }, [sp], #32
    ld1     { v12.1d - v15.1d }, [sp], #32
    ret


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

#endif
