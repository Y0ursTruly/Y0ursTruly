git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
. ./emsdk_env.sh

#building with emcc is as follows
#  echo -e "CC = emcc\nCXX = em++\nAR=emar\nRANLIB=emranlib\nCXXFLAGS=-msimd128" >> Makefile
#  emmake make -j $(nproc) build-target-if-any
