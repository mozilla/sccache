#include <stdlib.h>

#define foo(x)                                                                 \
  {                                                                            \
    if (x) {                                                                   \
      abort();                                                                 \
    }                                                                          \
  }

void bar() { foo(0); }
