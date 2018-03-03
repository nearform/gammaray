package vulnfetcher

// Vulnerability describes a vulnerability
type Vulnerability struct {
	CVE         string
	Title       string
	Description string
	Versions    string
	References  string
}

// Package is a package. Not a map to allow multiple versions.
type Package struct {
	Name    string
	Version string
}

// VulnFetcher fetches vulnerabilities
type VulnFetcher interface {
	Fetch() error
	Add(component string, version string)
	Test() ([]Vulnerability, error)
}
