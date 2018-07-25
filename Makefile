all: clean install build

formatter:
	pigeon -o versionformatter/versionformatter.go versionformatter/versionformatter.peg

.PHONY: clean
clean:
	@rm -rf vendor || true
	@rm gammaray || true

build: formatter
	go build -v -race

install:
	go get github.com/golang/dep
	dep ensure

dev-install: install
	go get -u github.com/mgechev/revive
	go get -u github.com/mna/pigeon

ci-install: dev-install
	go get -u github.com/mattn/goveralls

test:
	go test -v -race ./...
	go vet ./...

ci-test: test
	goveralls

lint:
	revive -formatter stylish pathrunner/... vulnfetcher/...
