package main

import (
	"fmt"
	"os"

	"github.com/dgonzalez/gammaray/pathrunner"
	"github.com/dgonzalez/gammaray/vulnfetcher/ossvulnfetcher"
)

const OSSIndexURL = "https://ossindex.net/v2.0/package"

func main() {
	packages, err := pathrunner.Walk(os.Args[1])
	if err != nil {
		panic(err)
	}

	fetcher := ossvulnfetcher.New(OSSIndexURL)
	for _, singlePackage := range packages {
		vulnerabilities, err := fetcher.Test(singlePackage.Name, singlePackage.Version)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Package: %s\n", singlePackage.Name)
		if len(vulnerabilities) > 0 {
			for _, vulnerability := range vulnerabilities {
				fmt.Printf("\tCVE: %s Title: %s\n", vulnerability.CVE, vulnerability.Title)
			}
		} else {
			fmt.Printf("\tNo vulnerabilities found\n")
		}

	}

}
