FROM debian:stretch

RUN DEBIAN_FRONTEND=noninteractive apt-get -q update && \
    apt-get -q -y --no-install-recommends install \
        build-essential \
        automake \
        libtool \
        clang \
        git \
        ca-certificates && \
    apt-get -q clean && \
    apt-get -q -y autoremove && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --home /opt/newnode newnode

ADD ./ /opt/newnode
RUN chown -R 1000:1000 /opt/newnode

USER newnode
WORKDIR /opt/newnode
RUN git submodule init && git submodule update
RUN ./build.sh

EXPOSE 8006/tcp
EXPOSE 8007/tcp

CMD ["./client"]
