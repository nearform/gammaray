package vulnfetcher

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsImpactedByVulnerabilityInvalidVersion(t *testing.T) {
	_, err := IsImpactedByVulnerability("aaaa", "invalid version", nil)
	if diff := cmp.Diff(err.Error(), "1:1 (0): no match found, expected: \"!\", \"!=\", \"*\", \"<\", \"<=\", \"=\", \"==\", \">\", \">=\", \"X\", \"^\", \"x\", \"~\", [ \\t\\n\\r] or [0-9]"); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityInvalidVersion: invalid version error : (-got +want)\n%s", diff)
	}
}

func TestIsImpactedByVulnerabilityInvalidVulnerabilityVersion(t *testing.T) {
	_, err := IsImpactedByVulnerability("aaaa", "1.0.0", &Vulnerability{
		Versions: "invalid version",
	})
	if diff := cmp.Diff(err.Error(), "1:1 (0): no match found, expected: \"!\", \"!=\", \"*\", \"<\", \"<=\", \"=\", \"==\", \">\", \">=\", \"X\", \"^\", \"x\", \"~\", [ \\t\\n\\r] or [0-9]"); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityInvalidVulnerabilityVersion: invalid version error : (-got +want)\n%s", diff)
	}
}

func TestIsImpactedByVulnerabilityInvalidVulnerabilityFixedVersion(t *testing.T) {
	_, err := IsImpactedByVulnerability("aaaa", "1.0.5", &Vulnerability{
		Versions: "^1.0.0",
		Fixed:    "invalid version",
	})
	if diff := cmp.Diff(err.Error(), "1:1 (0): no match found, expected: \"!\", \"!=\", \"*\", \"<\", \"<=\", \"=\", \"==\", \">\", \">=\", \"X\", \"^\", \"x\", \"~\", [ \\t\\n\\r] or [0-9]"); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityInvalidVulnerabilityFixedVersion: invalid version error : (-got +want)\n%s", diff)
	}
}

func TestIsImpactedByVulnerabilityWithActualVuln(t *testing.T) {
	impacted, err := IsImpactedByVulnerability("aaaa", "1.0.5", &Vulnerability{
		Versions: "^1.0.0",
	})
	if err != nil {
		panic(err)
	}
	if diff := cmp.Diff(impacted, true); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityWithActualVuln: invalid version error : (-got +want)\n%s", diff)
	}
}

func TestIsImpactedByVulnerabilityWithFixedVuln(t *testing.T) {
	impacted, err := IsImpactedByVulnerability("aaaa", "1.0.5", &Vulnerability{
		Versions: "^1.0.0",
		Fixed:    ">1.0.4",
	})
	if err != nil {
		panic(err)
	}
	if diff := cmp.Diff(impacted, false); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityWithFixedVuln: invalid version error : (-got +want)\n%s", diff)
	}
}

func TestIsImpactedByVulnerabilityWithNotImpactingVuln(t *testing.T) {
	impacted, err := IsImpactedByVulnerability("aaaa", "1.0.5", &Vulnerability{
		Versions: "<1.0.0",
		Fixed:    "",
	})
	if err != nil {
		panic(err)
	}
	if diff := cmp.Diff(impacted, false); diff != "" {
		t.Errorf("TestIsImpactedByVulnerabilityWithNotImpactingVuln: invalid version error : (-got +want)\n%s", diff)
	}
}
