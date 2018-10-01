FROM debian:9.4-slim
LABEL maintainer igor.shmukler@nearform.com

RUN \
    cd ~ && \
    apt-get update -qq && \
    apt-get install -qqy \
        git-core build-essential wget curl && \
        wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz && \
        tar xvf go1.10.3.linux-amd64.tar.gz && \
        mv go /usr/local/ && \
        export GOROOT=/usr/local/go && \
        export GOBIN=/usr/local/bin && \
        export GOPATH=$HOME/Projects && \
        export PATH=$GOPATH/bin:$GOROOT/bin:$PATH && \
    rm -rf /var/lib/apt/lists/* && \
    go env GOPATH && \
    go get -u github.com/mna/pigeon && \
    git clone https://github.com/nearform/gammaray $GOPATH/src/github.com/nearform/gammaray && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
    cd $GOPATH/src/github.com/nearform/gammaray && make && \
    mv gammaray /usr/bin/
