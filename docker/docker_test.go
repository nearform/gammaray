package docker

import (
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestScanImageHelloWorld(t *testing.T) {
	vulns, err := ScanImage("gammaray-test-hello-world:1.0.0", "")
	if err != nil {
		panic(err)
	}
	numVulns := 0
	for provider, vulnList := range vulns {
		numVulns += len(vulnList)
		log.Print(provider, "> ", len(vulnList), " vulnerabilities:\n", vulnList)
	}
	if diff := cmp.Diff(numVulns, 0); diff != "" {
		t.Errorf("TestHelloWorld: vulnerabilities : (-got +want)\n%s", diff)
	}
}

func TestScanImageInsecureProject(t *testing.T) {
	vulns, err := ScanImage("gammaray-test-insecure-project:1.0.0", "")
	if err != nil {
		panic(err)
	}
	for provider, vulnList := range vulns {
		providerVulns := len(vulnList)
		log.Print(provider, "> ", providerVulns, " vulnerabilities:\n", vulnList)
		// both OSSIndex and NodeSWG report bassmaster-1.0.0 and its dep hoek-1.5.2
		if diff := cmp.Diff(providerVulns, 2); diff != "" {
			t.Errorf("TestInsecureProject: %s vulnerabilities : (-got +want)\n%s", provider, diff)
		}
	}
}
