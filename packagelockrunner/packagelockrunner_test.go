package packagelockrunner

import (
	log "github.com/sirupsen/logrus"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWalkHelloWorld(t *testing.T) {
	packages, err := PackageLockRunner{}.Walk("../test_data/hello-world")
	if err != nil {
		panic(err)
	}
	log.Println("TestWalkInsecureProject: packages:\n", packages)
	if diff := cmp.Diff(len(packages), 1); diff != "" {
		t.Errorf("TestHelloWorld: packages : (-got +want)\n%s", diff)
	}
}

func TestWalkInsecureProject(t *testing.T) {
	packages, err := PackageLockRunner{}.Walk("../test_data/insecure-project")
	if err != nil {
		panic(err)
	}
	log.Println("TestWalkInsecureProject: packages:\n", packages)
	if diff := cmp.Diff(len(packages), 4); diff != "" {
		t.Errorf("TestWalkInsecureProject: packages : (-got +want)\n%s", diff)
	}
}

func TestWalkHelloWorldNoPackageLock(t *testing.T) {
	_, err := PackageLockRunner{}.Walk("../test_data/hello-world-no-package-lock")
	if err == nil {
		panic(err)
	}
	if diff := cmp.Diff(err.Error(), "open ../test_data/hello-world-no-package-lock/package-lock.json: no such file or directory"); diff != "" {
		t.Errorf("TestWalkDevNull: err : (-got +want)\n%s", diff)
	}
}

func TestWalkNotInstalledSecureComplexProject(t *testing.T) {
	packages, err := PackageLockRunner{}.Walk("../test_data/not-installed-secure-complex-project")
	if err != nil {
		panic(err)
	}
	log.Println("TestWalkNotInstalledSecureComplexProject: packages:\n", packages)
	if diff := cmp.Diff(len(packages), 1132); diff != "" {
		t.Errorf("TestWalkNotInstalledSecureComplexProject: packages : (-got +want)\n%s", diff)
	}
}

func TestWalkDevNull(t *testing.T) {
	_, err := PackageLockRunner{}.Walk("/dev/null")
	if err == nil {
		panic(err)
	}
	if diff := cmp.Diff(err.Error(), "</dev/null> is not a directory, make sure to put the proper path to your project"); diff != "" {
		t.Errorf("TestWalkDevNull: err : (-got +want)\n%s", diff)
	}
}

func TestWalkDoesNotExist(t *testing.T) {
	_, err := PackageLockRunner{}.Walk("./does-not-exist")
	if err == nil {
		t.Errorf("TestWalkDoesNotExist: given ./does-not-exist does not exist, it should Error !")
	}
}
