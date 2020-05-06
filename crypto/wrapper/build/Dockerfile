FROM ubuntu:16.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    libc6-dev \
    make \
    pkg-config \
    curl \
    ca-certificates \
    git \
    wget \
    libssl-dev \
	python \
	python3-pip \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
#   CMake
# ---------------------------------------------------------------------------
ENV CMAKE_VERSION_MAJOR=3
ENV CMAKE_VERSION_MINOR=12
ENV CMAKE_VERSION_PATCH=4
ENV CMAKE_VERSION=${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}.${CMAKE_VERSION_PATCH}

RUN cd && \
    wget https://cmake.org/files/v${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}/cmake-${CMAKE_VERSION}-Linux-x86_64.sh && \
    bash cmake-${CMAKE_VERSION}-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr/local && \
    rm cmake-${CMAKE_VERSION}-Linux-x86_64.sh


RUN pip3 install protobuf
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10

# install golang
ENV GOLANG_VERSION 1.14.2
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 6272d6e940ecb71ea5636ddb5fab3933e087c1356173c61f4a803895e947ebb3

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
    && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf golang.tar.gz \
    && rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"