package nodeswg

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	unarr "github.com/gen2brain/go-unarr"
	"github.com/nearform/gammaray/nodepackage"
	"github.com/nearform/gammaray/vulnfetcher"
	log "github.com/sirupsen/logrus"
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
	tmpDir := path.Join(os.TempDir(), base64.StdEncoding.EncodeToString([]byte(n.DatabaseURL)))
	os.Mkdir(tmpDir, os.ModePerm)

	log.Info("Temporary directory for NodeSWG Database <", n.DatabaseURL, ">:\n", tmpDir)
	destFilePath := path.Join(tmpDir, "nodeswg.zip")
	unzipFolder := path.Join(tmpDir, "nodeswg")
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

	log.Debugln("Downloading NodeSWG Database into <", destFilePath, ">")
	_, err = io.Copy(destFile, response.Body)
	if err != nil {
		return err
	}
	log.Debugln("Opening NodeSWG Database Archive in <", destFilePath, ">")

	a, err := unarr.NewArchive(destFilePath)
	if err != nil {
		return err
	}

	log.Debugln("Decompressing NodeSWG Database in <", unzipFolder, ">")
	err = a.Extract(unzipFolder)
	if err != nil {
		return err
	}

	err = filepath.Walk(vulnFolder, func(path string, f os.FileInfo, err error) error {

		if strings.HasSuffix(path, ".json") {
			log.Debugln("Opening NodeSWG Database file <", path, ">")
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

	log.Infoln("Found <", len(n.vulnerabilities), "> entries in NodeSWG Database")

	return err
}

// Test tests for a vulnerability on a single package
func (n *Fetcher) Test(pkg nodepackage.NodePackage) ([]vulnfetcher.Vulnerability, error) {
	return n.TestAll(append(make([]nodepackage.NodePackage, 0, 1), pkg))
}

// TestAll tests for a vulnerability
func (n *Fetcher) TestAll(pkgs []nodepackage.NodePackage) ([]vulnfetcher.Vulnerability, error) {
	var vulnerabilities []vulnfetcher.Vulnerability

	log.Infoln("✨ Node SWG Vulnerability check for <", len(pkgs), "> packages")
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
			log.Debugln("✨ Node SWG Vulnerability check for ", name, "(", version, ") in <", vuln.Versions, "> excluding <", vuln.Fixed, ">")
			isImpacted, err := vulnfetcher.IsImpactedByVulnerability(name, version, &vuln)
			if err != nil {
				return nil, err
			}
			if !isImpacted {
				continue
			}
			log.Infoln("✨ Node SWG Vulnerability found for ", name, "(", version, ") in <", vuln.Versions, "> excluding <", vuln.Fixed, ">")
			vulnerabilities = append(vulnerabilities, vuln)
		}

	}
	return vulnerabilities, nil
}
