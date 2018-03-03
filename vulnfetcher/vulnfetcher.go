package vulnfetcher

// Vulnerability describes a vulnerability
type Vulnerability struct {
	CVE         string
	Title       string
	Description string
	Versions    string
	References  string
}

// VulnFetcher fetches vulnerabilities
type VulnFetcher interface {
	Fetch() error
	Add(component string, version string)
	Test() ([]Vulnerability, error)
}
