// This tests sccache's ability to handle a known bug in cl.exe
// More information: https://github.com/mozilla/sccache/issues/1725
__pragma(warning(push))
__pragma(warning(disable: 4668))
// cl.exe during compilation will correctly ignore 4668 here (undefined define)
// during preprocessing, it will not ignore 4668
// sccache must explicitly ignore this warning when preprocessing (to figure out the cache key)
#if UNDEFINED_MACRO_TRIGGERING_C4668
#error "This error should be unreachable"
#endif
__pragma(warning(pop))

// Minimal reproducible example for errors from user code
// More information: https://github.com/mozilla/sccache/issues/2250
#pragma warning(disable : 4002)

#define F(x, y)

int main() {
  F(2, , , , , , 3, , , , , , ) // C4002

  return 0;
}
