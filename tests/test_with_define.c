#include <stdio.h>

#if !defined(SCCACHE_TEST_DEFINE)
#error SCCACHE_TEST_DEFINE is not defined
#endif

void foo() { printf("hello world\n"); }
