FROM docker.io/fedora:42

# Install essential tools for e2e testing
RUN dnf install -y \
    nginx \
    nftables \
    net-tools \
    iputils \
    iproute \
    tcpdump \
    wireshark-cli \
    nmap-ncat \
    jq \
    procps-ng \
    util-linux \
    && dnf clean all

# Ensure nftables service is available
RUN systemctl enable nftables || true
