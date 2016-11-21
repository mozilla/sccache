[![Build Status](https://travis-ci.org/mozilla/sccache.svg?branch=master)](https://travis-ci.org/mozilla/sccache) [![Build status](https://ci.appveyor.com/api/projects/status/h4yqo430634pmfmt?svg=true)](https://ci.appveyor.com/project/luser/sccache2)

sccache is a shared compiler cache. It's similar to [ccache](https://ccache.samba.org/), but with two major differences:
* sccache supports Microsoft Visual C++
* sccache supports storing its cache in Amazon S3, for sharing a cache among multiple builders

This is a reimplementation of the original [sccache](https://github.com/glandium/sccache) in Rust. The original has been in production use at Mozilla for several years with great results.
