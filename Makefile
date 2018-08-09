all: clean install build

formatter: peg

peg:
	pigeon -o versionformatter/versionformatter.go versionformatter/versionformatter.peg
	pigeon -o yarnlockparser/yarnlockparser.go yarnlockparser/yarnlockparser.peg

.PHONY: clean
clean:
	@rm -rf vendor || true
	@rm gammaray || true

build: peg
	go build -v -race

install:
	go get github.com/golang/dep
	dep ensure

build-test-docker-images:
	docker build test_data/hello-world/ -t gammaray-test-hello-world:1.0.0
	docker build test_data/insecure-project/ -t gammaray-test-insecure-project:1.0.0

dev-install: install build-test-docker-images
	go get -u github.com/kyoh86/richgo
	go get -u github.com/mgechev/revive
	go get -u github.com/mna/pigeon

ci-install: dev-install
	go get -u github.com/mattn/goveralls

verbose-test:
	@richgo test -v -race ./... | sed ''/'PASS |'/s//`printf "✅\033[32mPASS\033[0m"`/'' | sed ''/'FAIL |'/s//`printf "❌\033[31mFAIL\033[0m"`/''
	@go vet ./...

test:
	@richgo test -v -race ./... | grep -v -P "     \|\s(?!ok)"| sed ''/'PASS |'/s//`printf "✅\033[32mPASS\033[0m"`/'' | sed ''/'FAIL |'/s//`printf "❌\033[31mFAIL\033[0m"`/''
	@go vet ./...

coverage:
	@richgo test -v -race -cover ./... | grep -P "START|SKIP |PASS |FAIL |COVER|ok  	github.com/nearform/gammaray" | sed ''/'PASS | '/s//`printf "✅\033[32mPASS\033[0m"`/'' | sed ''/'FAIL | '/s//`printf "❌\033[31mFAIL\033[0m"`/'' | sed ''/'COVER|'/s//`printf "\033[34mCOVER\033[0m"`/'' | sed ''/'SKIP |'/s//`printf "⚠️\033[36m.SKIP\033[0m"`/''
	@go vet ./...

ci-test: test
	goveralls

lint:
	revive -formatter stylish pathrunner/... vulnfetcher/...
