# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.145.1/containers/rust/.devcontainer/base.Dockerfile

FROM mcr.microsoft.com/vscode/devcontainers/rust:0-1

# Substrate-compatible Rust version.
# Pin rust to a specific version of nightly that contains all the required components (some releases don't include 
# rust fmt or rls). In order to check for more recent complete nightly releases run `rustup install --profile complete nightly`.
ARG RUST_VERSION=1.66.1
RUN rustup install $RUST_VERSION \
    && rustup update \
    && rustup default $RUST_VERSION \
    && rustup component add rls rust-analysis rust-src clippy rustfmt llvm-tools-preview \
    && rustup target add wasm32-unknown-unknown --toolchain $RUST_VERSION

# Substrate and rust compiler dependencies.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        cmake \
        build-essential \
        clang \
        libclang-dev \
        lld

# Install sccache for cached builds
ARG SCCACHE_VER="0.2.15"

RUN curl -fsSLo /tmp/sccache.tgz \
    https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VER}/sccache-v0.2.15-x86_64-unknown-linux-musl.tar.gz \
    && tar -xzf /tmp/sccache.tgz -C /tmp --strip-components=1 \
    && mv /tmp/sccache /usr/bin && chmod +x /usr/bin/sccache \
    && rm -rf /tmp/*

ENV RUSTC_WRAPPER=sccache

# Node, npm and yarn for front-end stuff.
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

# add protobuf compiler
RUN apt-get update && apt-get install -y protobuf-compiler


# Remove unnecessary packages.
RUN apt -y autoremove