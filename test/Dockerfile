FROM ubuntu:24.04

# Install necessary build tools and kernel dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libncurses-dev \
    bison \
    flex \
    libssl-dev \
    bc \
    wget \
    git \
    vim \
    cargo \
    pahole \
    libelf-dev \
    rsync \
    xz-utils \
    cpio \
    zstd \
    kmod \
    binutils-dev \
    libelf-dev \
    libiberty-dev \
    golang \
    sudo


# Set the working directory inside the container
WORKDIR /kernel

# Optional: add non-root user with sudo access for security
RUN useradd -u 842100 -m -s /bin/bash deku
# set id for deku user with current host user id

RUN usermod -aG sudo deku
RUN mkdir /home/deku/.cache
RUN chown deku:deku /home/deku/.cache
RUN chmod 777 /home/deku/.cache
ENV HOME /home/deku/
USER deku
