package vulnfetcher

// Vulnerability describes a vulnerability
type Vulnerability struct {
	CVE         string
	Title       string
	Description string
}

// VulnFetcher fetches vulnerabilities
type VulnFetcher interface {
	Fetch()
	Test(component string, version string) ([]Vulnerability, error)
}
