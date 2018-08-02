package ossvulnfetcher

import (
	"fmt"
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nearform/gammaray/pathrunner"
	"github.com/spacemeshos/go-spacemesh/assert"
)

func TestParseCVEFromTitleWithCVEContainingTitle(t *testing.T) {
	res := ParseCVEFromTitle("[CVE-2018-3728]  Improper Access Control")
	fmt.Println("TestParseCVEFromTitleWithCVEContainingTitle result:", res)
	if diff := cmp.Diff(res, "CVE-2018-3728"); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithCVEContainingTitle: CVE parsing from title : (-got +want)\n%s", diff)
	}
}

func TestParseCVEFromTitleWithoutCVEContainingTitle(t *testing.T) {
	res := ParseCVEFromTitle("Improper Access Control")
	fmt.Println("TestParseCVEFromTitleWithoutCVEContainingTitle result:", res)
	if diff := cmp.Diff(res, ""); diff != "" {
		t.Errorf("TestParseCVEFromTitleWithoutCVEContainingTitle: CVE parsing from title : (-got +want)\n%s", diff)
	}
}

func TestTestExistingPackageWithoutCVE(t *testing.T) {
	fetcher := New("https://ossindex.net/api/v3/component-report")
	err := fetcher.Fetch()
	assert.NoErr(t, err)

	var packages []pathrunner.NodePackage
	packages = append(packages, pathrunner.NodePackage{Name: "request", Version: "1.0.0"})
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

	var packages []pathrunner.NodePackage
	vulnerabilities, err := fetcher.TestAll(append(packages, pathrunner.NodePackage{Name: "bassmaster", Version: "1.0.0"}))
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 1); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
	if diff := cmp.Diff(vulnerabilities[0].CVE, "CVE-2014-7205"); diff != "" {
		t.Errorf("TestTestExistingPackageWithCVE: CVE : (-got +want)\n%s", diff)
	}
	if diff := cmp.Diff(vulnerabilities[0].Title, "[CVE-2014-7205]  Improper Control of Generation of Code (\"Code Injection\")"); diff != "" {
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

	var packages []pathrunner.NodePackage
	vulnerabilities, err := fetcher.TestAll(append(packages, pathrunner.NodePackage{Name: "@babel/code-frame", Version: "7.0.0-beta.47"}))
	assert.NoErr(t, err)

	log.Print(vulnerabilities)
	if diff := cmp.Diff(len(vulnerabilities), 0); diff != "" {
		t.Errorf("TestTestExistingPackageHavingNamespace: vulnerabilities length : (-got +want)\n%s", diff)
		return
	}
}
