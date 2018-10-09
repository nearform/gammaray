# Gamma Ray
[![Go Report Card](https://goreportcard.com/badge/github.com/nearform/gammaray)](https://goreportcard.com/report/github.com/nearform/gammaray)
![Travis](https://travis-ci.org/nearform/gammaray.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/nearform/gammaray/badge.svg?branch=master)](https://coveralls.io/github/nearform/gammaray?branch=master)

Gammaray is a software that helps developers to look for vulnerabilities on their Node.js
applications. Its pluggable infrastructure makes very easy to write an integration with
several vulnerabilities databases.

## Get It

In order to get it just run:

```console
$> go get github.com/nearform/gammaray
```
Once it is finished, you should have the `gammaray` binary in your `GOPATH/bin` folder.

## Build it

```console
$> make
```

## Usage

Gammaray comes as a single binary so you only need to run it passing your project as argument:

```console
$> gammaray <path-to-your-node-app>
```

Gammaray supports the following flags:

`-path` - path to directory where package.json is located

`-image` - docker image to scan

`-log-level` - valid values: `panic` | `fatal` | `error` | `warn` | `info` | `debug`. The default is `info`.

`-ignore-list` - path to JSON file with CVE/CWE ignore array
The sample file is shown below:
```
[
  {"CVE": "CWE-400", "description": "We ignore this because it does not affect us"},
  {"CVE": "CVE-2015-8851", "description": "We ignore this because it does not affect us"}
]
```

And that is all, all the vulnerabilities that affect your packages will be displayed.

## Contributing

### As a developer

Clone the repository, then start hacking, PRs are welcome !

```console
$> mkdir -p $GOPATH/src/github.com/nearform/
$> cd $GOPATH/src/github.com/nearform/
$> git clone https://github.com/nearform/gammaray.git
$> cd gammaray
$> make dev-install
```

### As security provider

You want to be integrated? Contact me [here](https://www.linkedin.com/in/david-gonzalez-microservices/)
