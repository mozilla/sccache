noinst_LIBRARIES = libbasedirs.a
# Use absolute path for source file - autoconf will substitute abs_srcdir and abs_builddir
libbasedirs_a_SOURCES = $(abs_srcdir)/main.cpp
# Override default includes to use absolute paths
AM_CPPFLAGS = -I$(abs_srcdir) -I$(abs_srcdir)/include
# Include directory will be passed via CXXFLAGS with absolute path
