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

build-test-docker-images:
	docker build test_data/hello-world/ -t gammaray-test-hello-world:1.0.0
	docker build test_data/insecure-project/ -t gammaray-test-insecure-project:1.0.0

dev-install: install build-test-docker-images
	go get -u github.com/mgechev/revive
	go get -u github.com/mna/pigeon

ci-install: dev-install
	go get -u github.com/mattn/goveralls

test:
	go test -v -race ./...
	go vet ./...

coverage:
	go test -v -race -cover ./...
	go vet ./...

ci-test: test
	goveralls

lint:
	revive -formatter stylish pathrunner/... vulnfetcher/...
