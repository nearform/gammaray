package main

import (
	"fmt"
	"os"

	"github.com/nearform/gammaray/pathrunner"
	"github.com/nearform/gammaray/vulnfetcher/nodeswg"
	"github.com/nearform/gammaray/vulnfetcher/ossvulnfetcher"
)

// OSSIndexURL URL for OSSIndex. Is not a hardcoded value to facilitate testing.
const OSSIndexURL = "https://ossindex.net/v2.0/package"
const nodeswgURL = "https://github.com/nodejs/security-wg/archive/master.zip"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gammaray <folder>")
		os.Exit(1)
	}

	packages, err := pathrunner.Walk(os.Args[1])
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	ossFetcher := ossvulnfetcher.New(OSSIndexURL)
	err = ossFetcher.Fetch()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	nodeswgFetcher := nodeswg.New(nodeswgURL)
	err = nodeswgFetcher.Fetch()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	for _, singlePackage := range packages {
		vulnerabilitiesOSS, err := ossFetcher.Test(singlePackage.Name, singlePackage.Version)
		// vulnerabilitiesNodeSWG, err := nodeswgFetcher.Test(singlePackage.Name, singlePackage.Version)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if len(vulnerabilitiesOSS) > 0 {
			fmt.Printf("\tPackage: %s (%s)\n", singlePackage.Name, singlePackage.Version)
			for _, vulnerability := range vulnerabilitiesOSS {
				fmt.Printf("\t\t- Vulnerability (OSS Index):\n")
				fmt.Printf("\t\t\t- CVE: %s\n\t\tTitle: %s\n\t\tVersions: %s\n\t\tFixed: %s\n\t\tMore Info: [%s]\n",
					vulnerability.CVE,
					vulnerability.Title,
					vulnerability.Versions,
					vulnerability.Fixed,
					vulnerability.References,
				)
			}
		}

		vulnerabilitiesNodeSWG, err := nodeswgFetcher.Test(singlePackage.Name, singlePackage.Version)
		if len(vulnerabilitiesNodeSWG) > 0 {
			fmt.Printf("\tPackage: %s\n", singlePackage.Name)
			for _, vulnerability := range vulnerabilitiesNodeSWG {
				fmt.Printf("\t\t- Vulnerability (Node Security Working Group):\n")
				fmt.Printf("\t\t\t- CVE: %s\n\t\tTitle: %s\n\t\tVersions: %s\n\t\tFixed: %s\n\t\tMore Info: [%s]\n",
					vulnerability.CVE,
					vulnerability.Title,
					vulnerability.Versions,
					vulnerability.Fixed,
					vulnerability.References,
				)
			}
		}
	}

}
