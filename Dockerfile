FROM debian:bookworm@sha256:133a1f2aa9e55d1c93d0ae1aaa7b94fb141265d0ee3ea677175cdb96f5f990e5 as base
RUN apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build ccache build-essential ca-certificates ccache cmake curl make pkg-config python3 python3-dev python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel python3-venv python3-sphinx unzip bluez-tools bluez libusb-1.0-0 clang-format libglib2.0-dev libpixman-1-dev libgcrypt20-dev virtualenv libslirp-dev && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/*
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN python3 -m pip install --break-system-packages --user pycodestyle

FROM base AS esp-idf

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.1.2
ARG ESP_IDF_COMMIT=482a8fb2d78e3b58eb21b26da8a5bedf90623213
RUN mkdir ~/esp && cd ~/esp && git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive --shallow-submodules https://github.com/espressif/esp-idf.git
RUN cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh esp32 esp32s3

FROM base AS esp-qemu

# These ARGs are easily parseable (eg by HWI)
ARG ESP_QEMU_BRANCH=esp-develop-8.1.2-20231017
ARG ESP_QEMU_COMMIT=9f1e6f1e048f5198d2e055389ab0b13930b046b1
RUN git clone --quiet --depth 1 --branch ${ESP_QEMU_BRANCH} --single-branch --recursive --shallow-submodules https://github.com/espressif/qemu.git \
&& cd qemu && git checkout ${ESP_QEMU_COMMIT}

RUN cd qemu && ./configure --target-list=xtensa-softmmu --prefix=/opt \
    --enable-gcrypt \
    --disable-sanitizers \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-sdl --disable-gtk --enable-slirp \
    && ninja -C build install && rm -fr /qemu

FROM esp-idf
COPY --from=esp-qemu /opt /opt
COPY requirements.txt /
COPY pinserver/requirements.txt /ps_requirements.txt
SHELL ["/bin/bash", "-c"]
RUN virtualenv -p python3 /venv && source /venv/bin/activate && pip install --require-hashes -r /requirements.txt -r /ps_requirements.txt
