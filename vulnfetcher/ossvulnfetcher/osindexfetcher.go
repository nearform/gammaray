package ossvulnfetcher

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/davecgh/go-spew/spew"
)

// OSSPackageRequest request for a package
type OSSPackageRequest struct {
	Pm      string `json:"pm"`
	Name    string `json:"name"`
	Version string `json:"-"`
}
type OSSPackageMultipleRequest struct {
	ossPackages []OSSPackageRequest
}

// OSSPackageResponse response for a package request
type OSSPackageResponse struct {
	Vulnerabilities []OSSVulnerability `json:"vulnerabilities"`
}

// OSSVulnerability vulnerability for a package response
type OSSVulnerability struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVE         string   `json:"cve"`
	Versions    []string `json:"versions"`
	References  []string `json:"references"`
}

// OSSIndexFetcher fetches the node.js security vulnerabilities
type OSSIndexFetcher struct {
	URL      string
	packages []OSSPackageRequest
}

// New creates a new instance of OSSIndexFetcher
func New(URL string) *OSSIndexFetcher {
	return &OSSIndexFetcher{URL: URL}
}

// Fetch does nothing as it is API based. No need to download anything.
func (n *OSSIndexFetcher) Fetch() error {
	// Nothing to do here. API based.
	return nil
}

// Add adds a package to the list of packages of the app
func (n *OSSIndexFetcher) Add(name string, version string) {
	n.packages = append(n.packages, OSSPackageRequest{Pm: "npm", Name: name, Version: version})
}

// Test tests for a package
func (n *OSSIndexFetcher) Test(name string, version string) {
	request := &OSSPackageMultipleRequest{n.packages}
	data, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}
	response, err := http.Post(n.URL, "application/json", bytes.NewReader(data))
	if response.StatusCode > 299 || response.StatusCode < 200 {
		panic("Unsuccessful status code: " + string(response.StatusCode))
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	// request := &OSSPackageRequest{Pm: "npm", Name: name}
	// data, err := json.Marshal([]*OSSPackageRequest{request})
	// if err != nil {
	// 	panic(err)
	// }
	// response, err := http.Post(n.URL, "application/json", bytes.NewReader(data))
	// if err != nil {
	// 	return nil, err
	// }
	//
	// if response.StatusCode >= 500 {
	// 	return nil, errors.New("Error: OSSIndex is unavailable")
	// }
	//
	// responseData, err := ioutil.ReadAll(response.Body)
	// if err != nil {
	// 	return nil, err
	// }
	//
	var structuredResponse []OSSPackageResponse
	unmarshalError := json.Unmarshal(responseData, &structuredResponse)
	if unmarshalError != nil {
		panic(unmarshalError)
	}
	spew.Dump(structuredResponse)
	// packageResponse := structuredResponse[0]
	// var vulnerabilities []vulnfetcher.Vulnerability
	// for _, vulnerability := range packageResponse.Vulnerabilities {
	// 	processedVulnerability := vulnfetcher.Vulnerability{
	// 		CVE:         vulnerability.CVE,
	// 		Title:       vulnerability.Title,
	// 		Description: vulnerability.Description,
	// 		Versions:    strings.Join(vulnerability.Versions, " "),
	// 		References:  strings.Join(vulnerability.References, " "),
	// 	}
	// 	vulnerabilities = append(vulnerabilities, processedVulnerability)
	// }
	//
	// return vulnerabilities, nil
}
