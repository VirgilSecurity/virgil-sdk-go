# Virgil crypto

This README describes how to manage a new version of Virgil crypto.

## Package structure

- The current folder contains adopted cryptography functions for common cases.
- The wrapper folder contains the C wrapper, pre-build libraries and build scripts.
	- `foundation`, `phe` are auto generated libraries from [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c).
	- `build` folder contains docker files and scripts for build pre-build C libs.
	- `pkg` folder contains pre-build C libs for different platforms.

## Update auto generated libraries

Copy everything from the `./wrapper/go/*` folder in https://github.com/VirgilSecurity/virgil-crypto-c and paste it into the `./crypto/wrapper`.

## Update pre-build libraries

The following command only updates a local version of the Virgil GO SDK. After, you have to run tests and commit changes.

### Requirements

- Requirements for [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c#build-from-sources)
- `go` >= 1.12

### Mac OS

Execute the script from the root of the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/wrapper/build/build_c_crypto.sh
```

### Linux

Supports two versions:
- for old linux kernel (old version of compiler)
- and modern linux version.

#### Legacy linux

##### Native

To support older version amd64 gcc < 5 and clang < 7  with 2.14 Linux kernel, execute the following script from the root of project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} PREBUILD_SUFIX=__legacy_os ./crypto/wrapper/build/build_c_crypto.sh
```

##### Via docker

- Build docker image
	- navigate to `./crypto/wrapper/build`
	- build `docker build -t ccrypto -f Dockerfile_legacy .` image 
- Build pre-build libraries
	- run docker from the project root `docker run -it --rm -v $PWD:/app ccrypto bash`
	- run `pip install protobuf` command inside a docker container
	- run `BRANCH={VIRGIL_CRYPTO_C_BRANCH} /app/crypto/wrapper/build/build_c_crypto.sh` script inside a docker container

#### Modern linux

##### Native
Execute the following script from the root of the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/wrapper/build/build_c_crypto.sh
```

##### Via docker

- Build docker image
	- Go to `./crypto/wrapper/build`
	- build image `docker build -t ccrypto .`
- Build pre-build libraries
	- run docker from the project root `docker run -it --rm -v $PWD:/app ccrypto bash`
	- inside docker container `BRANCH={VIRGIL_CRYPTO_C_BRANCH} /app/crypto/wrapper/build/build_c_crypto.sh`

### Windows

Execute the following script from the project root, make sure mingw-w64 is installed without spaces in its path

```bash
> ./crypto/wrapper/build/build_c_crypto.ps1 -branch={VIRGIL_CRYPTO_C_BRANCH}
```
