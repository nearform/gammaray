package nodeswg

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nearform/gammaray/nodepackage"
)

func TestFetch(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./test_data/test-data.zip")
		}),
	)
	defer server.Close()
	nodeFetcher := New(server.URL)
	err := nodeFetcher.Fetch()
	assert.NoError(t, err)
	assert.Len(t, nodeFetcher.vulnerabilities, 1, "number of vulns")
}

func TestFetchNoServer(t *testing.T) {
	nodeFetcher := New("weeeee")
	err := nodeFetcher.Fetch()
	assert.Error(t, err)
}

func TestTestExistingPackage(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./test_data/test-data.zip")
		}),
	)
	nodeFetcher := New(server.URL)
	err := nodeFetcher.Fetch()
	assert.NoError(t, err)

	vulnerabilities, err := nodeFetcher.Test(nodepackage.NodePackage{Name: "bassmaster", Version: "1.0"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(vulnerabilities), "number of vulns")
	assert.Equal(t, "CVE-2014-7205", vulnerabilities[0].CVE, "CVE")
	assert.Equal(t, "Arbitrary JavaScript Execution", vulnerabilities[0].Title, "Title")
	assert.True(t, strings.HasPrefix(vulnerabilities[0].Description, "A vulnerability exists in bassmaster"), "Description")
	assert.Equal(t, "<=1.5.1", vulnerabilities[0].Versions, "Version")
	assert.True(t, strings.HasPrefix(vulnerabilities[0].References, "https://www.npmjs.org/package/bassmaster"))
}

func TestTestExistingPackageWithFixedVersion(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./test_data/test-data.zip")
		}),
	)
	nodeFetcher := New(server.URL)
	err := nodeFetcher.Fetch()
	assert.NoError(t, err)

	vulnerabilities, err := nodeFetcher.Test(nodepackage.NodePackage{Name: "bassmaster", Version: "1.6.0"})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(vulnerabilities), "number of vulns")
}

func TestTestUnexistingPackage(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./test_data/test-data.zip")
		}),
	)
	nodeFetcher := New(server.URL)
	err := nodeFetcher.Fetch()
	assert.NoError(t, err)

	vulnerabilities, err := nodeFetcher.Test(nodepackage.NodePackage{Name: "test", Version: "unexisting"})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(vulnerabilities), "number of vulns")
}
