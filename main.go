package main

import (
	"fmt"
	"os"

	"github.com/dgonzalez/gammaray/pathrunner"
	"github.com/dgonzalez/gammaray/vulnfetcher/ossvulnfetcher"
)

// OSSIndexURL URL for OSSIndex. Is not a hardcoded value to facilitate testing.
const OSSIndexURL = "https://ossindex.net/v2.0/package"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gammaray <folder>")
		os.Exit(1)
	}

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

		if len(vulnerabilities) > 0 {
			fmt.Printf("Package: %s\n", singlePackage.Name)
			for _, vulnerability := range vulnerabilities {
				fmt.Printf("\t- Vulnerability:\n")
				fmt.Printf("\t\t- CVE: %s\n\t\tTitle: %s\n\t\tVersions: %s\n\t\tMore Info: %s",
					vulnerability.CVE,
					vulnerability.Title,
					vulnerability.Versions,
					vulnerability.References,
				)
			}
		}

	}

}
