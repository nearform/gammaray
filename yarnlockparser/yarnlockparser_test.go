package yarnlockparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseYarnLockHelloWorld(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/hello-world/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnLockHelloWorld: could not open test data file: %q", err)
	}

	res, err := ParseYarnLock(string(content))
	if err != nil {
		t.Errorf("TestParseYarnLockHelloWorld: Error during parsing: %q", err)
	}
	fmt.Println("TestParseYarnLockHelloWorld result:", res, "\n", err)
	if diff := cmp.Diff(len(res), 0); diff != "" {
		t.Errorf("TestParseYarnLockHelloWorld: after ParseYarnLock : (-got +want)\n%s", diff)
	}
}

func TestParseYarnLockHelloWorldAllOpts(t *testing.T) {
	stats := Stats{}
	content, err := ioutil.ReadFile("../test_data/hello-world/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnLockHelloWorldAllOpts: could not open test data file: %q", err)
	}

	res, err := ParseYarnLock(string(content), Debug(true), Memoize(true), AllowInvalidUTF8(true), Entrypoint("Input"), Entrypoint(""), MaxExpressions(12800000), Statistics(&stats, "no match"))
	if err != nil {
		t.Errorf("TestParseYarnLockHelloWorldAllOpts: Error during parsing: %q", err)
	}
	fmt.Println("TestParseYarnLockHelloWorldAllOpts result:", res, "\n", err)
	if diff := cmp.Diff(len(res), 0); diff != "" {
		t.Errorf("TestParseYarnLockHelloWorldAllOpts: after ParseYarnLock : (-got +want)\n%s", diff)
	}
	b, err := json.MarshalIndent(stats.ChoiceAltCnt, "", "  ")
	if err != nil {
		log.Panicln(err)
	}
	fmt.Println(string(b))
}

func TestParseYarnLockHelloWorldSmallMaxExpression(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/hello-world/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnLockHelloWorldSmallMaxExpression: could not open test data file: %q", err)
	}

	_, err = ParseYarnLock(string(content), MaxExpressions(1))
	if err == nil {
		t.Errorf("TestParseYarnLockHelloWorldSmallMaxExpression: it should Error hitting MaxExpression: %q", err)
	}
	if diff := cmp.Diff(err.Error(), "yarn.lock:1:1 (0): rule Input: max number of expresssions parsed"); diff != "" {
		t.Errorf("TestParseYarnLockHelloWorldSmallMaxExpression: after ParseYarnLock, error should be : (-got +want)\n%s", diff)
	}
}

func TestParseYarnLockInsecureProject(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/insecure-project/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnLockInsecureProject: could not open test data file: %q", err)
	}

	res, err := ParseYarnLock(string(content)) //, Debug(true))
	if err != nil {
		t.Errorf("TestParseYarnLockInsecureProject: Error during parsing: %q", err)
	}
	fmt.Println("TestParseYarnLockInsecureProject result:", res, "\n", err)
	if diff := cmp.Diff(len(res), 3); diff != "" {
		t.Errorf("TestParseYarnLockInsecureProject: after ParseYarnLock : (-got +want)\n%s", diff)
	}
}

func TestParseYarnNotInstalledInsecureComplexProject(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/not-installed-insecure-complex-project/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnLockInsecureProject: could not open test data file: %q", err)
	}

	res, err := ParseYarnLock(string(content)) //, Debug(true))
	if err != nil {
		t.Errorf("TestParseYarnLockInsecureProject: Error during parsing: %q", err)
	}
	fmt.Println("TestParseYarnLockInsecureProject result:", res, "\n", err)
	if diff := cmp.Diff(len(res), 245); diff != "" {
		t.Errorf("TestParseYarnLockInsecureProject: after ParseYarnLock : (-got +want)\n%s", diff)
	}
}

func TestParseYarnNotInstalledSecureComplexProject(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/not-installed-secure-complex-project/yarn.lock")
	if err != nil {
		t.Errorf("TestParseYarnNotInstalledSecureComplexProject: could not open test data file: %q", err)
	}

	res, err := ParseYarnLock(string(content)) //, Debug(true))
	if err != nil {
		t.Errorf("TestParseYarnNotInstalledSecureComplexProject: Error during parsing: %q", err)
	}
	fmt.Println("TestParseYarnNotInstalledSecureComplexProject result:", res, "\n", err)
	if diff := cmp.Diff(len(res), 948); diff != "" {
		t.Errorf("TestParseYarnNotInstalledSecureComplexProject: after ParseYarnLock : (-got +want)\n%s", diff)
	}
}

func TestParseYarnLockInvalidFile(t *testing.T) {
	content, err := ioutil.ReadFile("../test_data/insecure-project/package-lock.json")
	if err != nil {
		t.Errorf("TestParseYarnLockInvalidFile: could not open test data file: %q", err)
	}

	_, err = ParseYarnLock(string(content))
	if err == nil {
		t.Errorf("TestParseYarnLockInvalidFile: Invalid file should not give results")
	}
	if diff := cmp.Diff(err.Error(), "yarn.lock:1:1 (0): no match found, expected: \"#\" or [ \\t]"); diff != "" {
		t.Errorf("TestParseYarnNotInstalledSecureComplexProject: after ParseYarnLock : (-got +want)\n%s", diff)
	}
}
