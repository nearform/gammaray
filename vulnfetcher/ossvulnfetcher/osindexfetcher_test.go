package ossvulnfetcher

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nearform/gammaray/nodepackage"
	"github.com/spacemeshos/go-spacemesh/assert"
)

func TestParseCVEFromTitleWithCVEContainingTitle(t *testing.T) {
	res, title := ParseCVEFromTitle("[CVE-2018-3728]  Improper Access Control")
	fmt.Println("TestParseCVEFromTitleWithCVEContainingTitle result:", res, "/", title)
	if diff := cmp.Diff(res, "CVE-2018-3728"); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithCVEContainingTitle: CVE parsing from title : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(title, "Improper Access Control"); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithCVEContainingTitle: remaining title : (-got +want)\n%s", diff)
	}
}

func TestParseCVEFromTitleWithoutCVEContainingTitle(t *testing.T) {
	res, title := ParseCVEFromTitle("Improper Access Control")
	fmt.Println("TestParseCVEFromTitleWithoutCVEContainingTitle result:", res, "/", title)
	if diff := cmp.Diff(res, ""); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithoutCVEContainingTitle: CVE parsing from title : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(title, "Improper Access Control"); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithoutCVEContainingTitle: remaining title : (-got +want)\n%s", diff)
	}
}

func TestParseCWEFromTitleWithCWEContainingTitle(t *testing.T) {
	res, title := ParseCWEFromTitle("CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')")
	fmt.Println("TestParseCWEFromTitleWithCWEContainingTitle result:", res, "/", title)
	if diff := cmp.Diff(res, "CWE-400"); diff != "" {
		t.Errorf("TestParseCWEFromTitleWithCWEContainingTitle: CWE parsing from title : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(title, "Uncontrolled Resource Consumption ('Resource Exhaustion')"); diff != "" {
		t.Errorf("TestParseCWEFromTitleWithCWEContainingTitle: remaining title : (-got +want)\n%s", diff)
	}
}

func TestParseCWEFromTitleWithoutCWEContainingTitle(t *testing.T) {
	res, title := ParseCWEFromTitle("Uncontrolled Resource Consumption ('Resource Exhaustion')")
	fmt.Println("TestParseCWEFromTitleWithoutCWEContainingTitle result:", res, "/", title)
	if diff := cmp.Diff(res, ""); diff != "" {
		t.Errorf("TestParseCWEFromTitleWithoutCWEContainingTitle: CWE parsing from title : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(title, "Uncontrolled Resource Consumption ('Resource Exhaustion')"); diff != "" {
		t.Errorf("TestParseCWEFromTitleWithoutCWEContainingTitle: remaining title : (-got +want)\n%s", diff)
	}
}

func TestTestExistingPackageWithoutCVE(t *testing.T) {
	fetcher := New("https://ossindex.net/api/v3/component-report")
	err := fetcher.Fetch()
	assert.NoErr(t, err)

	var packages []nodepackage.NodePackage
	packages = append(packages, nodepackage.NodePackage{Name: "request", Version: "1.0.0"})
	log.Print("packages:", packages)
	vulnerabilities, err := fetcher.TestAll(packages)
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 1); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
	if diff := cmp.Diff(vulnerabilities[0].CVE, ""); diff != "" {
		t.Errorf("TestTestExistingPackageWithoutCVE: CVE : (-got +want)\n%s", diff)
	}
}

func TestTestExistingPackageWithCVE(t *testing.T) {
	fetcher := New("https://ossindex.net/api/v3/component-report")
	err := fetcher.Fetch()
	assert.NoErr(t, err)

	var packages []nodepackage.NodePackage
	vulnerabilities, err := fetcher.TestAll(append(packages, nodepackage.NodePackage{Name: "bassmaster", Version: "1.0.0"}))
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 1); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
	if diff := cmp.Diff(vulnerabilities[0].CVE, "CVE-2014-7205"); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: CVE : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(vulnerabilities[0].Title, "Improper Control of Generation of Code (\"Code Injection\")"); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: title : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(vulnerabilities[0].Description, "Eval injection vulnerability in the internals.batch function in lib/batch.js in the bassmaster plugin before 1.5.2 for the hapi server framework for Node.js allows remote attackers to execute arbitrary Javascript code via unspecified vectors."); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: description : (-got +want)\n%s", diff)
	}
}

func TestTestExistingPackageHavingNamespaceAndNoKnownVulns(t *testing.T) {
	fetcher := New("https://ossindex.net/api/v3/component-report")
	err := fetcher.Fetch()
	assert.NoErr(t, err)

	var packages []nodepackage.NodePackage
	vulnerabilities, err := fetcher.TestAll(append(packages, nodepackage.NodePackage{Name: "@babel/code-frame", Version: "7.0.0-beta.47"}))
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 0); diff != "" {
		t.Errorf("TestTestExistingPackageHavingNamespace: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
}

func TestTestEmptyPackageList(t *testing.T) {
	fetcher := New("https://ossindex.net/api/v3/component-report")
	err := fetcher.Fetch()
	assert.NoErr(t, err)

	var packages []nodepackage.NodePackage
	vulnerabilities, err := fetcher.TestAll(packages)
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 0); diff != "" {
		t.Errorf("TestTestExistingPackageHavingNamespace: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
}
