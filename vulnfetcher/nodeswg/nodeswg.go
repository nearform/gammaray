package nodeswg

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dgonzalez/gammaray/vulnfetcher"
	"github.com/mholt/archiver"
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
	Title              string   `json:"title"`
	References         string   `json:"references"`
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

	filepath.Walk(vulnFolder, func(path string, f os.FileInfo, err error) error {

		if strings.HasSuffix(path, ".json") {
			jsonFile, err := os.Open(path)
			defer jsonFile.Close()
			if err != nil {
				return err
			}

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

	return nil
}

// Test tests for a vulnerability
func (n *Fetcher) Test(module string, version string) ([]vulnfetcher.Vulnerability, error) {
	var vulnerabilities []vulnfetcher.Vulnerability

	for _, vulnerability := range n.vulnerabilities {
		if module == vulnerability.Module {
			vulnerabilities = append(vulnerabilities, vulnfetcher.Vulnerability{
				CVE:         strings.Join(vulnerability.CVES, " "),
				Title:       vulnerability.Title,
				Description: vulnerability.Overview,
				Versions:    vulnerability.VulnerableVersions,
				References:  vulnerability.References,
			})
		}
	}

	return vulnerabilities, nil
}
