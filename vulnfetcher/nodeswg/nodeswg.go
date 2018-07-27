package nodeswg

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mholt/archiver"
	"github.com/nearform/gammaray/pathrunner"
	"github.com/nearform/gammaray/vulnfetcher"
)

// Fetcher fetches node community vulnerabilities
type Fetcher struct {
	DatabaseURL     string
	vulnerabilities []Vulnerability
}

// Vulnerability a single vulnerability
type Vulnerability struct {
	Module             string   `json:"module_name"`
	CVES               []string `json:"cves"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	FixedVersions      string   `json:"patched_versions"`
	Title              string   `json:"title"`
	References         []string `json:"references"`
	Overview           string   `json:"overview"`
}

// New creates a NodeSWGFetcher
func New(URL string) *Fetcher {
	return &Fetcher{URL, make([]Vulnerability, 0)}
}

// Fetch builds the database from nodeswg on github
func (n *Fetcher) Fetch() error {
	destFilePath := path.Join(os.TempDir(), "nodeswg.zip")
	unzipFolder := path.Join(os.TempDir(), "nodeswg")
	vulnFolder := path.Join(unzipFolder, "security-wg-master", "vuln", "npm")

	os.Mkdir(unzipFolder, os.ModePerm)

	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	response, err := http.Get(n.DatabaseURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	_, err = io.Copy(destFile, response.Body)
	if err != nil {
		return err
	}

	archiver.Zip.Open(destFilePath, unzipFolder)

	err = filepath.Walk(vulnFolder, func(path string, f os.FileInfo, err error) error {

		if strings.HasSuffix(path, ".json") {
			jsonFile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer jsonFile.Close()

			jsonParser := json.NewDecoder(jsonFile)
			var nodeVulnerability Vulnerability
			err = jsonParser.Decode(&nodeVulnerability)
			if err != nil {
				return err
			}
			n.vulnerabilities = append(n.vulnerabilities, nodeVulnerability)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// Test tests for a vulnerability on a single package
func (n *Fetcher) Test(pkg pathrunner.NodePackage) ([]vulnfetcher.Vulnerability, error) {
	return n.TestAll(append(make([]pathrunner.NodePackage, 0, 1), pkg))
}

// TestAll tests for a vulnerability
func (n *Fetcher) TestAll(pkgs []pathrunner.NodePackage) ([]vulnfetcher.Vulnerability, error) {
	var vulnerabilities []vulnfetcher.Vulnerability

	for _, pkg := range pkgs {
		name := pkg.Name
		version := pkg.Version

		for _, vulnerability := range n.vulnerabilities {
			if name != vulnerability.Module {
				continue
			}
			var vuln = vulnfetcher.Vulnerability{
				Package:        name,
				PackageVersion: version,
				CVE:            strings.Join(vulnerability.CVES, " "),
				Title:          vulnerability.Title,
				Description:    vulnerability.Overview,
				Versions:       vulnerability.VulnerableVersions,
				Fixed:          vulnerability.FixedVersions,
				References:     strings.Join(vulnerability.References, "\n\n"),
			}
			log.Println("✨ Node SWG Vulnerability check for ", name, "(", version, ") in '", vuln.Versions, "' excluding '", vuln.Fixed, "'")
			isImpacted, err := vulnfetcher.IsImpactedByVulnerability(name, version, &vuln)
			if err != nil {
				return nil, err
			}
			if !isImpacted {
				continue
			}
			log.Println("✨ Node SWG Vulnerability found for ", name, "(", version, ") in '", vuln.Versions, "' excluding '", vuln.Fixed, "'")
			vulnerabilities = append(vulnerabilities, vuln)
		}

	}
	return vulnerabilities, nil
}
