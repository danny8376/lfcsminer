#include "asm_common.h"

#define _func(name) \
.align 4 ; \
.type name, %function ; \
__func(name)
