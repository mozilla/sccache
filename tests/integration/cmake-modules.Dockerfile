FROM silkeh/clang:21-trixie
RUN apt-get update -qq && apt-get install -y -qq cmake ninja-build python3 && rm -rf /var/lib/apt/lists/*
