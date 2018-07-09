all: install build

formatter:
	pigeon -o versionformatter/versionformatter.go versionformatter/versionformatter.peg

build: formatter
	go build -v -race

install:
	go get github.com/golang/dep
	dep ensure

dev-install: install
	go get -u github.com/mgechev/revive
	go get -u github.com/mna/pigeon

test:
	go test -v -race ./...
	go vet ./...

lint:
	revive -formatter stylish pathrunner/... vulnfetcher/...
