package ossvulnfetcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/nearform/gammaray/vulnfetcher"
)

// OSSComponentReport is a Component vulnerability report
type OSSComponentReport struct {
	Coordinates     string `json:"coordinates"` // Component coordinates as package-url
	Description     string `json:"description"` // Component description
	Reference       string `json:"reference"`   // Component details reference
	Vulnerabilities []OSSVulnerability
}

// OSSVulnerability is a vulnerability for a component vulnerability report
type OSSVulnerability struct {
	ID          string  `json:"id"`          // Public identifier
	Title       string  `json:"title"`       // Vulnerability title
	Description string  `json:"description"` // Vulnerability description
	CvssScore   float32 `json:"cvssScore"`   // CVSS score
	CvssVector  string  `json:"cvssVector"`  // CVSS vector
	Cwe         string  `json:"cwe"`         // CWE
	Reference   string  `json:"reference"`   // Vulnerability details reference
}

// OSSIndexFetcher fetches the node.js security vulnerabilities
type OSSIndexFetcher struct {
	URL string
}

// OSSPackageRequest is the body for querying "coordinates" (a coordinate is a string containing <package manager>:<name>@<version> of a package)
type OSSPackageRequest struct {
	Coordinates []string `json:"coordinates"`
}

// New creates a new instance of OSSIndexFetcher
func New(URL string) *OSSIndexFetcher {
	return &OSSIndexFetcher{URL}
}

// Fetch does nothing as it is API based. No need to download anything.
func (n *OSSIndexFetcher) Fetch() error {
	// Nothing to do here. API based.
	return nil
}

// BuildCoordinate builds the "coordinates" of an npm package according to its name and version
func BuildCoordinate(name string, version string) string {
	var namespace = strings.Replace(name, "@", "", -1)
	var data = "npm:" + namespace + "@" + version
	return data
}

// ParseCVEFromTitle parses CVE identifier from title field ( it used to be a dedicated field in API v2, in API v3 it must be parsed...)
func ParseCVEFromTitle(title string) string {
	re := regexp.MustCompile("^\\s*\\[(CVE.*?)\\]")
	res := re.FindStringSubmatch(title)

	if len(res) != 2 {
		return ""
	}
	log.Print("CVE Found in Title: ", res[1])
	return res[1]
}

// Test checks for a package vulnerabilities in OSSIndex
func (n *OSSIndexFetcher) Test(name string, version string) ([]vulnfetcher.Vulnerability, error) {
	if len(name) == 0 {
		return nil, errors.New("Error: Invalid empty name for package to check")
	}
	if len(version) == 0 {
		return nil, errors.New("Error: Invalid empty version for package to check")
	}
	var coordinates [1]string
	coordinates[0] = BuildCoordinate(name, version)
	request := &OSSPackageRequest{Coordinates: coordinates[:]}
	data, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}

	// Execute the request
	response, err := http.Post(n.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	s := response.StatusCode
	responseData, err := ioutil.ReadAll(response.Body)
	switch {
	case s >= 500:
		log.Fatal(response)
		return nil, fmt.Errorf("Error: OSSIndex is unavailable:\n%s\nclient request resulting in error: %s", responseData, data)
	case s == 429:
		return nil, fmt.Errorf("Error: OSSIndex : 'Too many requests':\n%s\nclient request resulting in error: %s", responseData, data)
	case s >= 400:
		// Don't retry, it was client's fault
		return nil, fmt.Errorf("Error: OSSIndex client error:\n%s\nclient request resulting in error: %s", responseData, data)
	}

	if err != nil {
		return nil, err
	}

	var structuredResponse []OSSComponentReport
	unmarshalError := json.Unmarshal(responseData, &structuredResponse)
	if unmarshalError != nil {
		return nil, unmarshalError
	}

	packageResponse := structuredResponse[0]
	var vulnerabilities []vulnfetcher.Vulnerability
	for _, vulnerability := range packageResponse.Vulnerabilities {
		processedVulnerability := vulnfetcher.Vulnerability{
			CVE:         ParseCVEFromTitle(vulnerability.Title),
			Title:       vulnerability.Title,
			Description: vulnerability.Description,
			Versions:    version,
		}
		log.Println("✨ OSS Vulnerability check for ", name, "(", version, ")")
		vulnerabilities = append(vulnerabilities, processedVulnerability)
	}

	return vulnerabilities, nil
}
