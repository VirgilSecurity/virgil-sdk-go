#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TEMPDIR=`mktemp -d`
OS=`go env GOOS`
ARCH=`go env GOARCH`
if [[ -z "$BRANCH" ]]; then
  BRANCH=master;
fi

PREBUILD_FOLDER=${OS}_${ARCH}${PREBUILD_SUFIX}

git clone -b $BRANCH https://github.com/VirgilSecurity/virgil-crypto-c.git $TEMPDIR && \
mkdir $TEMPDIR/build && \
cd $TEMPDIR/build && \
cmake \
    -DVIRGIL_WRAP_GO=OFF \
    -DVIRGIL_LIB_PYTHIA=OFF \
    -DVIRGIL_INSTALL_HDRS=ON \
    -DVIRGIL_INSTALL_LIBS=ON \
    -DVIRGIL_INSTALL_CMAKE=OFF \
    -DVIRGIL_INSTALL_DEPS_HDRS=ON \
    -DVIRGIL_INSTALL_DEPS_LIBS=ON \
    -DVIRGIL_INSTALL_DEPS_CMAKE=OFF \
    -DENABLE_TESTING=OFF \
    -DVIRGIL_C_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DVIRGIL_POST_QUANTUM=ON \
    -DED25519_REF10=OFF \
    -DED25519_AMD64_RADIX_64_24K=ON \
    -DCMAKE_INSTALL_PREFIX=../wrappers/go/binaries .. && \
make -j10 && make -j10 install && \
cd $TEMPDIR/wrappers/go && \
if [[ -d "./binaries/lib64" ]]; then
  mv ./binaries/lib64 ./binaries/lib
fi && \
go test ./...

RETRES=$?
echo $RETRES
if [ "$RETRES" == "0" ]; then
  rm -rf $SCRIPT_FOLDER/../pkg/$PREBUILD_FOLDER;
  mkdir -p $SCRIPT_FOLDER/../pkg/$PREBUILD_FOLDER/{lib,include};
  cp -R $TEMPDIR/wrappers/go/binaries/include/* $SCRIPT_FOLDER/../pkg/$PREBUILD_FOLDER/include;
  cp -R $TEMPDIR/wrappers/go/binaries/lib/* $SCRIPT_FOLDER/../pkg/$PREBUILD_FOLDER/lib;
fi
rm -rf $TEMPDIR

# /Users/tochka/gowork/crypto/go/v5