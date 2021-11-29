FROM archlinux

RUN pacman --noconfirm -Syyu
RUN pacman --noconfirm -S --needed git base-devel
RUN git clone https://aur.archlinux.org/yay.git && \
    cd yay && \
    source './PKGBUILD' && \
    pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed --asdeps "${makedepends[@]}" "${depends[@]}"
RUN pacman -S --noconfirm cmocka \
    cmake \
    clang \
    llvm \
    lld \
    llvm-libs \
    pkg-config \
    libgcrypt


# Build include-what-you-use from Git, since there is no compatible release for LLVM 13 yet.
# Tracking issue https://github.com/include-what-you-use/include-what-you-use/issues/974
RUN cd /tmp && \
    git clone https://github.com/include-what-you-use/include-what-you-use.git && \
    cd include-what-you-use && \
    mkdir build && \
    cd build && \
    cmake -G "Unix Makefiles" -DCMAKE_PREFIX_PATH=/usr/lib/llvm-13 .. && \
    make install && \
    cd ../.. && \
    rm -rf include-what-you-use

RUN pacman -S --noconfirm valgrind
RUN mkdir -p /build/test

COPY . /build
RUN rm -rf /build/CMakeCache.txt /build/build

WORKDIR /build
