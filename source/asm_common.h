#ifdef __APPLE__

#define __func(name) \
.global _##name ; \
_##name:

#else

#define __func(name) \
.global name ; \
name:

#endif
