sudo pacman -S --needed cmake libdaq libdnet flex gcc hwloc luajit openssl libpcap pcre2 pkgconf zlib patchelf
git clone https://github.com/snort3/libdaq.git

rm -r build
mkdir build
export SNORT_DIR="$(pwd)/install"

export DAQ_BUILD_DIR="$(pwd)/libdaq/build"
export DAQ_LIBRARY_DIR="$DAQ_BUILD_DIR/lib"
export DAQ_INCLUDE_DIR="$DAQ_BUILD_DIR/include"

cmake -S . -B build \
  -DCMAKE_PREFIX_PATH="$DAQ_BUILD_DIR" \
  -DCMAKE_INSTALL_PREFIX="$SNORT_DIR"

cmake --build build -j$(nproc)
cmake --install build
patchelf --set-rpath "$DAQ_LIBRARY_DIR" "$SNORT_DIR/bin/snort"
