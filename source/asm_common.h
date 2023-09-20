#ifdef __APPLE__

#define _func(name) \
.global _##name ; \
_##name:

#else

#define _func(name) \
.global name ; \
name:

#endif
