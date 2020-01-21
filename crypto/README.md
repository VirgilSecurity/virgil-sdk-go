# Virgil crypto

There are described how to manage new version of crypto.

## Package structure

- Current folder contain adopted cryptography functions for common cases.
- `wrapper` folder contains C wrapper, pre-build libraries and build scripts.
	- `foundation`, `phe`, `ratchet` are auto generated libraries from [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c).
	- `build` folder contains docker files and scripts for build pre-build C libs.
	- `pkg` folder contains pre-build C libs for different platforms.

## Update auto generated libraries

Copy past from `./wrapper/go/*` folders from https://github.com/VirgilSecurity/virgil-crypto-c into `./crypto/wrapper`

## Update pre-build libraries

The following command only update local version of the Virgil GO SDK. After you need run tests and commit changes.

### Requirements

- Requirements for [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c#build-from-sources)
- `go` >= 1.12

### Mac OS

Execute script from the root the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/wrapper/build/build_c_crypto.sh
```

### Linux

Support two versions for old linux kernel (old version of compiler) and modern linux version.

#### Legacy linux

##### Native

For support older version linux amd64 gcc < 5 and clang < 7  with 2.14 Linux kernel
Execute script from the root the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} PREBUILD_SUFIX=__legacy_os ./crypto/wrapper/build/build_c_crypto.sh
```

##### Via docker

- Build docker image
	- Go to `./crypto/wrapper/build`
	- build image `docker build -t ccrypto -f Dockerfile_legacy.`
- Build pre-build libraries
	- run docker from root project `docker run -it --rm -v $PWD:/app ccrypto bash`
	- inside docker container `pip install protobuf`
	- inside docker container `BRANCH={VIRGIL_CRYPTO_C_BRANCH} /app/crypto/wrapper/build/build_c_crypto.sh`

#### Modern linux

##### Native
Execute script from the root the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/wrapper/build/build_c_crypto.sh
```

##### Via docker

- Build docker image
	- Go to `./crypto/wrapper/build`
	- build image `docker build -t ccrypto .`
- Build pre-build libraries
	- run docker from root project `docker run -it --rm -v $PWD:/app ccrypto bash`
	- inside docker container `BRANCH={VIRGIL_CRYPTO_C_BRANCH} /app/crypto/wrapper/build/build_c_crypto.sh`

### Windows

Execute script from the root the project

```bash
> ./crypto/wrapper/build/build_c_crypto.ps1 -branch={VIRGIL_CRYPTO_C_BRANCH}
```
