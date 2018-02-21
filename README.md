# Gamma Ray
[![Go Report Card](https://goreportcard.com/badge/github.com/dgonzalez/gammaray)](https://goreportcard.com/report/github.com/dgonzalez/gammaray)
![Travis](https://travis-ci.org/dgonzalez/gammaray.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/dgonzalez/gammaray/badge.svg?branch=travis)](https://coveralls.io/github/dgonzalez/gammaray?branch=travis)

Gamm Ray is a software that helps developers to look for vulnerabilities on their Node.js
applications. Its pluggable infrastructure makes very easy to write an integration with
several vulnerabilities databases.

## Get It

In order to get it just run:

```
go get github.com/dgonzalez/gammaray
```
Once it is finished, you should have the `gammaray` binary in your `GOPATH/bin` folder.

## Build it

We use `dep` to manage the dependencies for `gammaray`. In order to build it, run:

```
dep ensure
go build
```

## Usage

Gammaray comes as a single binary so you only need to run it passing your project as argument:

```
gammaray <path-to-your-node-app>
```

And that is all, all the vulnerabilities that affect your packages will be displayed.

## Contributing

Are you a developer and want to contribute? Please be my guest.

Are you a security provider who wants to be integrated? Contact me [here](https://www.linkedin.com/in/david-gonzalez-microservices/)
