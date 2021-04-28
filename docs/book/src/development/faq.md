# FAQ

Q: Why not [bazel][bazel]?
A: Bazel makes a few very opinionated assumptions such as hermetic builds being a given, which is a good property in general but non-trivial to achieve for now. There is another issue regarding the fact that bazel is very dominant. It assumes it’s the entry tool and we want to stick with cargo while maintaining the option to plug in sccache/cachepot.

Q: Why not [buildbarn][buildbarn]?
A: It is the backend caching infra for bazel.

Q: Why not [synchronicty][synchronicty]?
A: It’s in a very early, experimental stage and uses components with low activity and low community involvement.

[bazel]: https://bazel.build
[buildbarn]: https://github.com/buildbarn
[synchronicty]: https://github.com/iqlusioninc/synchronicity
