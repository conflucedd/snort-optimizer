git checkout v3.0.19

rm -r build
mkdir build
./bootstrap
./configure --prefix="$(pwd)/build"
make -j$(nproc)
make install
