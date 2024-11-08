#! /usr/bin/env bash
set -eu

export DEBIAN_FRONTEND=noninteractive

get_cuda_deb() {
    local deb="$(                                 \
        wget --no-hsts -q -O- "${1}/Packages"     \
    | grep -P "^Filename: \./${2}(.*)\.deb$"      \
    | sort -Vr | head -n1 | cut -d' ' -f2         \
    )";
    if [ -z "$deb" ]; then
        echo "Error: No matching .deb found for '${1}' and '${2}'" >&2
        return 1
    fi
    wget --no-hsts -q -O "/tmp/${deb#./}" "${1}/${deb#./}";
    echo -n "/tmp/${deb#./}";
}

VERSION="$1";

NVARCH="$(uname -p)";

if test "$NVARCH" = aarch64; then
    NVARCH="sbsa";
fi

OSNAME="$(
    . /etc/os-release;
    major="$(cut -d'.' -f1 <<< "${VERSION_ID}")";
    minor="$(cut -d'.' -f2 <<< "${VERSION_ID}")";
    echo "$ID$((major - (major % 2)))${minor}";
)";

CUDA_HOME="/usr/local/cuda";

cuda_repo_base="https://developer.download.nvidia.com/compute/cuda/repos";
cuda_repo="${cuda_repo_base}/${OSNAME}/${NVARCH}";

cuda_ver="$VERSION";
cuda_ver="$(grep -Po '^[0-9]+\.[0-9]+' <<< "${cuda_ver}")";
cuda_ver="${cuda_ver/./-}";

if ! dpkg -s cuda-keyring; then
    sudo apt-get install -y --no-install-recommends   \
        "$(get_cuda_deb "${cuda_repo}" cuda-keyring)" \
        ;
fi

PKGS=();
PKGS+=("cuda-toolkit-${cuda_ver}");

sudo apt-get update;
sudo apt-get install -y --no-install-recommends "${PKGS[@]}";

if ! test -L "${CUDA_HOME}"; then
    # Create /usr/local/cuda symlink
    sudo ln -s "${CUDA_HOME}-${cuda_ver}" "${CUDA_HOME}";
fi

export PATH="$PATH:$CUDA_HOME/bin"

which -a nvcc
nvcc --version

cat <<EOF | tee -a "$GITHUB_ENV"
CUDA_HOME=$CUDA_HOME
CUDA_PATH=$CUDA_HOME
PATH=$PATH
EOF

rm /tmp/*.deb
