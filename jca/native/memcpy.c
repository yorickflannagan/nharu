#if defined(__GNUC__)
#include <string.h>
__asm__(".symver memcpy, memcpy@GLIBC_2.2.5");
void *__wrap_memcpy(void *dest, const void *src, size_t n) { return memcpy(dest, src, n); }
#endif
