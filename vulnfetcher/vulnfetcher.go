package vulnfetcher

import (
	"fmt"
	"log"

	"github.com/Masterminds/semver"
	"github.com/nearform/gammaray/versionformatter"
)

// Vulnerability describes a vulnerability
type Vulnerability struct {
	Package        string
	PackageVersion string
	CVE            string
	CWE            string
	Title          string
	Description    string
	Versions       string
	Fixed          string
	References     string
}

// VulnerabilityReport stores the list of all vulnerabilities/weaknesses found by provider
type VulnerabilityReport map[string][]Vulnerability

// VulnFetcher fetches vulnerabilities
type VulnFetcher interface {
	Fetch() error
	Test(component string, version string) ([]Vulnerability, error)
}

func tryToMakeValidVersion(version string) (string, error) {
	// return invalidPreRelease.ReplaceAllString(version, "-$1")
	return versionformatter.Format(version)
}

// IsImpactedByVulnerability checks if a given module with a given version is impacted by a vulnerability
func IsImpactedByVulnerability(module string, moduleVersion string, vulnerability *Vulnerability) (bool, error) {
	version, err := tryToMakeValidVersion(moduleVersion)
	if err != nil {
		fmt.Printf("Error parsing module version '%s'(%s): %q", module, moduleVersion, err)
		return true, err
	}
	log.Println("version", moduleVersion, "👉", version)
	ver, err := semver.NewVersion(version)
	if err != nil {
		fmt.Printf("Error parsing Package version of module '%s'(%s): %q", module, moduleVersion, err)
		return true, err
	}

	vulnVersions, err := tryToMakeValidVersion(vulnerability.Versions)
	log.Println("Vulnerable Versions", vulnerability.Versions, "👉", vulnVersions)
	if err != nil {
		fmt.Printf("Error parsing Vulnerability version range of module '%s'(%s): %q", module, moduleVersion, err)
		return true, err
	}
	rangeVuln, err := semver.NewConstraint(vulnVersions)
	if err != nil {
		fmt.Printf("Error parsing formatted Vulnerability version range of module '%s'(%s): %q", module, moduleVersion, err)
		return true, err
	}

	var isVuln = rangeVuln.Check(ver)
	if !isVuln {
		log.Println(module, "(", moduleVersion, ") is not subject to a known vulnerability or weakness ✅")
		return false, err
	}

	if vulnerability.Fixed == "" {
		log.Println(module, "(", moduleVersion, ") is subject to a known vulnerability or weakness! ❌")
		return true, nil
	}
	fixedVersions, err := tryToMakeValidVersion(vulnerability.Fixed)
	log.Println("fixedVersions", vulnerability.Fixed, "👉", fixedVersions)
	if err != nil {
		fmt.Printf("Error parsing Fixed version range of module '%s'(%s): %q", module, moduleVersion, err)
		return false, err
	}
	rangeFixed, err := semver.NewConstraint(fixedVersions)
	if err != nil {
		fmt.Printf("Error parsing formatted Fixed version range of module '%s'(%s): %q", module, moduleVersion, err)
		return false, err
	}

	var isFixed = rangeFixed.Check(ver)
	if isFixed {
		log.Println(module, "(", moduleVersion, ") is not subject to a known vulnerability or weakness ✅ (part of the fixed versions)")
	} else {
		log.Println(module, "(", moduleVersion, ") is subject to a known vulnerability or weakness! ❌ (not part of the fixed versions)")
	}

	return !isFixed, nil
}
