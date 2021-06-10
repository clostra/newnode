FROM ubuntu:focal

RUN apt-get -y update && \
	apt-get -y upgrade && \
	apt-get -y install build-essential clang git

# Are other dependencies required?  This is as far as I got in the alloted time.
#RUN apt-get -y install random-build-tool libtransitive-dependency-dev

WORKDIR /

# obtain the source code from GitHub
RUN git clone --recurse-submodules https://github.com/clostra/newnode.git
# or, move the files in `docker/` to the top-level directory, remove that last
# line, and uncomment the next one to use your local source code
#COPY . /newnode

WORKDIR /newnode
RUN ./build.sh
