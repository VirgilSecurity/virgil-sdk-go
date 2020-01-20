# Virgil crypto

There are described how to manage new version of crypto.

## Package structure

- Current folder contain adopted cryptography functions for common cases.
- `internal` folder contains C wrapper, pre-build libraries and build scripts.
- `foundation`, `phe`, `ratchet` are auto generated libraries from [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c).
- `build` folder contains docker files and scripts for build pre-build C libs.
- `pkg` folder contains pre-build C libs for different platforms.

## Update auto generated libraries

- Install [gsl](https://github.com/zeromq/gsl)
- Clone https://github.com/VirgilSecurity/virgil-crypto-c
- Go to the cloning folder
- Remove `./wrapper/go/*` except go.mod go.sum
- execute `./codegen.sh`  from the root the project
- Remove auto generated libraries in the Virgil GO SDK crypto (`./crypto/internal/`)
- Copy all folders from Virgil crypto C `./wrapper/go/*` into `./crypto/internal`

## Update pre-build libraries

The following command only update local version of the Virgil GO SDK. After you need run tests and commit changes.

### Requirements

- Requirements for [Virgil crypto C](https://github.com/VirgilSecurity/virgil-crypto-c#build-from-sources)
- `go` >= 1.12

### Mac OS

Execute script from the root the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/internal/build/build_c_crypto.sh
```

### Linux

#### Native
Execute script from the root the project

```bash
> BRANCH={VIRGIL_CRYPTO_C_BRANCH} ./crypto/internal/build/build_c_crypto.sh
```

#### Via docker

- Build docker image
	- Go to `./crypto/internal/build`
	- build image `docker build -t ccrypto .`
- Build pre-build libraries
	- run docker from root project `docker run -it --rm -v $PWD:/app ccrypto bash`
	- inside docker container `BRANCH={VIRGIL_CRYPTO_C_BRANCH} /app/crypto/internal/build/build_c_crypto.sh`

### Windows

Execute script from the root the project

```bash
> ./crypto/internal/build/build_c_crypto.ps1 -branch={VIRGIL_CRYPTO_C_BRANCH}
```
