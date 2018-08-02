package main

import (
	"fmt"
	"log"
	"os"

	"github.com/nearform/gammaray/pathrunner"
	"github.com/nearform/gammaray/vulnfetcher/nodeswg"
	"github.com/nearform/gammaray/vulnfetcher/ossvulnfetcher"
)

// OSSIndexURL URL for OSSIndex. Is not a hardcoded value to facilitate testing.
const OSSIndexURL = "https://ossindex.net/api/v3/component-report"
const nodeswgURL = "https://github.com/nodejs/security-wg/archive/master.zip"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gammaray <folder>")
		os.Exit(1)
	}

	f, err := os.OpenFile(".gammaray.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	packageList, err := pathrunner.Walk(os.Args[1])
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// keep only valid packages
	var packages []pathrunner.NodePackage
	for _, pkg := range packageList {
		if pkg.Name == "" {
			log.Print("Ignoring package with empty name")
			continue
		}
		if pkg.Version == "" {
			pkg.Version = "*"
		}
		packages = append(packages, pkg)
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

	vulnerabilitiesOSS, err := ossFetcher.TestAll(packages)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if len(vulnerabilitiesOSS) > 0 {
		fmt.Println("🚨 Some vulnerabilities found by OSS Index")
		var pkg string
		var pkgversion string
		for _, vulnerability := range vulnerabilitiesOSS {
			if vulnerability.Package != pkg && vulnerability.PackageVersion != pkgversion {
				fmt.Printf("\t📦 Package: %s (%s)\n", vulnerability.Package, vulnerability.PackageVersion)
			}
			pkg = vulnerability.Package
			pkgversion = vulnerability.PackageVersion

			fmt.Printf("\t\t- Vulnerability (OSS Index):\n")
			fmt.Printf("\t\t\tCVE: %s\n\t\t\tTitle: %s\n\t\t\tDescription: %s\n\t\t\tMore Info: [%s]\n",
				vulnerability.CVE,
				vulnerability.Title,
				vulnerability.Description,
				vulnerability.References,
			)
		}
	} else {
		fmt.Println("✅ No Vulnerability found by OSS Index")
	}

	vulnerabilitiesNodeSWG, err := nodeswgFetcher.TestAll(packages)
	if len(vulnerabilitiesNodeSWG) > 0 {
		fmt.Println("🚨 Some vulnerabilities found by Node Security Working Group")
		var pkg string
		var pkgversion string
		for _, vulnerability := range vulnerabilitiesNodeSWG {
			if vulnerability.Package != pkg && vulnerability.PackageVersion != pkgversion {
				fmt.Printf("\t📦 Package: %s (%s)\n", vulnerability.Package, vulnerability.PackageVersion)
			}
			pkg = vulnerability.Package
			pkgversion = vulnerability.PackageVersion
			fmt.Printf("\t\t- Vulnerability (Node Security Working Group):\n")
			fmt.Printf("\t\t\tCVE: %s\n\t\t\tTitle: %s\n\t\t\tVersions: %s\n\t\t\tFixed: %s\n\t\t\tDescription: %s\n\t\t\tMore Info: [%s]\n",
				vulnerability.CVE,
				vulnerability.Title,
				vulnerability.Versions,
				vulnerability.Fixed,
				vulnerability.Description,
				vulnerability.References,
			)
		}
	} else {
		fmt.Println("✅ No Vulnerability found by Node Security Working Group")
	}

}
