package vulnfetcher

import (
	"fmt"
	"gammaray/versionformatter"

	"github.com/Masterminds/semver"
)

// Vulnerability describes a vulnerability
type Vulnerability struct {
	CVE         string
	Title       string
	Description string
	Versions    string
	Fixed       string
	References  string
}

// VulnFetcher fetches vulnerabilities
type VulnFetcher interface {
	Fetch() error
	Test(component string, version string) ([]Vulnerability, error)
}

// var invalidPreRelease = regexp.MustCompile("\\.([a-zA-Z].+?)(\\s|$)")
// var majorMinorPatchPreReleaseBuild = regexp.MustCompile("\\d+\\.\\d+\\.\\d+\\-\\w+\\+[^ <>=~]")
// var majorMinorNoPatch = regexp.MustCompile("\\.([a-zA-Z].+?)(\\s|$)")

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
	fmt.Println("🐭 version", moduleVersion, "👉", version)
	ver, err := semver.NewVersion(version)
	if err != nil {
		fmt.Printf("Error parsing Package version of module '%s'(%s): %q", module, moduleVersion, err)
		return true, err
	}

	vulnVersions, err := tryToMakeValidVersion(vulnerability.Versions)
	fmt.Println("🐭 Vulnerable Versions", vulnerability.Versions, "👉", vulnVersions)
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
		fmt.Println("🐭", module, "(", moduleVersion, ") is not subject to a known vulnerability ✅")
		return false, err
	}

	if vulnerability.Fixed == "" {
		fmt.Println("🐭", module, "(", moduleVersion, ") is subject to a known vulnerability! ❌")
		return true, nil
	}
	fixedVersions, err := tryToMakeValidVersion(vulnerability.Fixed)
	fmt.Println("🐭 fixedVersions", vulnerability.Fixed, "👉", fixedVersions)
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
		fmt.Println("🐭", module, "(", moduleVersion, ") is not subject to a known vulnerability ✅ (part of the fixed versions)")
	} else {
		fmt.Println("🐭", module, "(", moduleVersion, ") is subject to a known vulnerability! ❌ (not part of the fixed versions)")
	}

	return !isFixed, nil
}
