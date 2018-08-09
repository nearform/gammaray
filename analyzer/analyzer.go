package analyzer

import (
	"errors"
	"fmt"

	"github.com/nearform/gammaray/nodepackage"
	"github.com/nearform/gammaray/packagelockrunner"
	"github.com/nearform/gammaray/pathrunner"
	"github.com/nearform/gammaray/vulnfetcher"
	"github.com/nearform/gammaray/vulnfetcher/nodeswg"
	"github.com/nearform/gammaray/vulnfetcher/ossvulnfetcher"
	"github.com/nearform/gammaray/yarnlockrunner"
	log "github.com/sirupsen/logrus"
)

// OSSIndexURL URL for OSSIndex. Is not a hardcoded value to facilitate testing.
const OSSIndexURL = "https://ossindex.net/api/v3/component-report"
const nodeswgURL = "https://github.com/nodejs/security-wg/archive/master.zip"

func runWalkers(path string, walkers []nodepackage.Walker) ([]nodepackage.NodePackage, error) {
	var errs []error
	var mainPackage []nodepackage.NodePackage
	for _, walker := range walkers {
		packageList, err := walker.Walk(path)
		if packageList != nil {
			if len(packageList) > 1 {
				return packageList, nil
			}
			// only found the main package, but no dependency using this method
			// just continue with other ways to check if we find more
			// can happen for example with pathrunner, if no 'npm i' has been done
			mainPackage = packageList
		}
		if err != nil {
			fmt.Println("⚠️", walker.ErrorContext(err), ":\n", err)
			errs = append(errs, err)
		}
	}
	if mainPackage != nil {
		return mainPackage, nil
	}
	if len(errs) == len(walkers) {
		return nil, errors.New("could not find any dependencies and all strategies to find them failed")
	}
	return nil, nil
}

func packagesCleanupAndDeduplication(packageList []nodepackage.NodePackage) []nodepackage.NodePackage {
	packageMap := make(map[string]nodepackage.NodePackage)
	for _, pkg := range packageList {
		if pkg.Name == "" {
			log.Debug("🔍 Ignoring package with empty name")
			continue
		}
		if pkg.Version == "" {
			pkg.Version = "*"
		}
		packageMap[pkg.Name+"@"+pkg.Version] = pkg
	}

	var packages []nodepackage.NodePackage
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}
	return packages
}

// Analyze analyzes a path to an installed (npm install) node package
func Analyze(path string, walkers ...nodepackage.Walker) (vulnfetcher.VulnerabilityReport, error) {
	fmt.Println("🔍 Will scan folder <", path, ">")
	if walkers == nil {
		walkers = []nodepackage.Walker{
			pathrunner.PathRunner{},
			packagelockrunner.PackageLockRunner{},
			yarnlockrunner.YarnLockRunner{},
		}
	}

	packageList, err := runWalkers(path, walkers)
	if err != nil {
		return nil, err
	}

	// keep only valid packages
	packages := packagesCleanupAndDeduplication(packageList)

	ossFetcher := ossvulnfetcher.New(OSSIndexURL)
	err = ossFetcher.Fetch()
	if err != nil {
		return nil, err
	}

	nodeswgFetcher := nodeswg.New(nodeswgURL)
	err = nodeswgFetcher.Fetch()
	if err != nil {
		return nil, err
	}

	vulnerabilitiesOSS, err := ossFetcher.TestAll(packages)
	if err != nil {
		return nil, err
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
			fmt.Printf("\t\t\tCVE: %s\n\t\t\tCWE: %s\n\t\t\tTitle: %s\n\t\t\tDescription: %s\n\t\t\tMore Info: [%s]\n",
				vulnerability.CVE,
				vulnerability.CWE,
				vulnerability.Title,
				vulnerability.Description,
				vulnerability.References,
			)
		}
	} else {
		fmt.Println("✅ No Vulnerability found by OSS Index")
	}

	vulnerabilitiesNodeSWG, err := nodeswgFetcher.TestAll(packages)
	if err != nil {
		return nil, err
	}
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

	report := vulnfetcher.VulnerabilityReport{
		"OSSIndex": vulnerabilitiesOSS,
		"NodeSWG":  vulnerabilitiesNodeSWG,
	}

	return report, nil
}
