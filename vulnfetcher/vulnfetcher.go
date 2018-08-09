package vulnfetcher

import (
	"fmt"

	"github.com/Masterminds/semver"
	"github.com/nearform/gammaray/versionformatter"
	log "github.com/sirupsen/logrus"
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
	TestAll(component string, version string) ([]Vulnerability, error)
}

func tryToMakeValidVersion(version string) (string, error) {
	// return invalidPreRelease.ReplaceAllString(version, "-$1")
	return versionformatter.Format(version)
}

// IsImpactedByVulnerability checks if a given module with a given version is impacted by a vulnerability
func IsImpactedByVulnerability(module string, moduleVersion string, vulnerability *Vulnerability) (bool, error) {
	version, err := tryToMakeValidVersion(moduleVersion)
	if err != nil {
		fmt.Printf("Error parsing module version '%s'(%s): %q\n", module, moduleVersion, err)
		return true, err
	}
	log.Debug("version", moduleVersion, "👉", version)
	ver, err := semver.NewVersion(version)
	if err != nil {
		fmt.Printf("Error parsing Package version of module '%s'(%s): %q\n", module, moduleVersion, err)
		return true, err
	}

	vulnVersions, err := tryToMakeValidVersion(vulnerability.Versions)
	log.Debug("Vulnerable Versions", vulnerability.Versions, "👉", vulnVersions)
	if err != nil {
		fmt.Printf("Error parsing Vulnerability version range of module '%s'(%s): %q\n", module, moduleVersion, err)
		return true, err
	}
	rangeVuln, err := semver.NewConstraint(vulnVersions)
	if err != nil {
		fmt.Printf("Error parsing formatted Fixed Vulnerability version range of module '%s'(%s): %q\n", module, moduleVersion, err)
		return true, err
	}

	var isVuln = rangeVuln.Check(ver)
	if !isVuln {
		log.Debug(module, "(", moduleVersion, ") is not subject to a known vulnerability or weakness ✅")
		return false, err
	}

	if vulnerability.Fixed == "" {
		log.Debug(module, "(", moduleVersion, ") is subject to a known vulnerability or weakness! ❌")
		return true, nil
	}
	fixedVersions, err := tryToMakeValidVersion(vulnerability.Fixed)
	log.Debug("fixedVersions", vulnerability.Fixed, "👉", fixedVersions)
	if err != nil {
		fmt.Printf("Error parsing Fixed version range of module '%s'(%s): %q\n", module, moduleVersion, err)
		return false, err
	}
	rangeFixed, err := semver.NewConstraint(fixedVersions)
	if err != nil {
		fmt.Printf("Error parsing formatted Fixed version range of module '%s'(%s): %q\n", module, moduleVersion, err)
		return false, err
	}

	var isFixed = rangeFixed.Check(ver)
	if isFixed {
		log.Info(module, "(", moduleVersion, ") is not subject to a known vulnerability or weakness ✅ (part of the fixed versions)")
	} else {
		log.Warn(module, "(", moduleVersion, ") is subject to a known vulnerability or weakness! ❌ (not part of the fixed versions)")
	}

	return !isFixed, nil
}
