FROM silkeh/clang:21-trixie
RUN apt-get update -qq && apt-get install -y -qq ninja-build python3 python3-pip \
    && pip install --break-system-packages cmake \
    && rm -rf /var/lib/apt/lists/*
