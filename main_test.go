package main

import (
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

var testLogFile = path.Join(os.TempDir(), "gammaray-log-test")

func cleanLogs() {
	os.Remove(testLogFile)
}

func TestHelloWorld(t *testing.T) {
	defer cleanLogs()
	err := (&Args{
		Image:   "",
		LogFile: testLogFile,
		Path:    "test_data/hello-world",
	}).Run()
	if err != nil {
		t.Error(err)
		return
	}
	info, error := os.Stat(testLogFile)
	if error != nil {
		t.Errorf("TestHelloWorld: Could not stat log file <%s>:\n%s", testLogFile, error)
	}
	log.Println("TestHelloWorld: log fileinfo:\n", info)

	if info.Size() == 0 {
		t.Errorf("TestHelloWorld: log size should not be 0!")
	}

}

func TestInsecureProject(t *testing.T) {
	defer cleanLogs()
	err := (&Args{
		Image:   "",
		LogFile: testLogFile,
		Path:    "test_data/insecure-project",
	}).Run()
	if err != nil {
		t.Error(err)
		return
	}
	info, error := os.Stat(testLogFile)
	if error != nil {
		t.Errorf("TestInsecureProject: Could not stat log file <%s>:\n%s", testLogFile, error)
	}
	log.Println("TestInsecureProject: log fileinfo:\n", info)

	if info.Size() == 0 {
		t.Errorf("TestInsecureProject: log size should not be 0!")
	}

}

func TestPathDoesNotExist(t *testing.T) {
	defer cleanLogs()
	err := (&Args{
		Image:   "",
		LogFile: testLogFile,
		Path:    "./does-not-exist",
	}).Run()

	if err == nil {
		t.Errorf("TestPathDoesNotExist: there should be an error when trying to analyze ./does-not-exist")
	}

	if diff := cmp.Diff(err.Error(), "could not find any dependencies and all strategies to find them failed"); diff != "" {
		t.Errorf("TestPathDoesNotExist: error : (-got +want)\n%s", diff)
	}
}

func TestPathIsEmpty(t *testing.T) {
	defer cleanLogs()

	os.Args = []string{""}

	err := (&Args{
		Image:   "",
		LogFile: testLogFile,
		Path:    "",
	}).Run()

	if err == nil {
		t.Errorf("TestPathIsEmpty: there should be an error when trying to analyze an empty path/empty image")
	}

	if diff := cmp.Diff(err.Error(), "you need to at least properly define a path or a docker image"); diff != "" {
		t.Errorf("TestPathIsEmpty: error : (-got +want)\n%s", diff)
	}
}

func TestImageHelloWorld(t *testing.T) {
	defer cleanLogs()
	err := (&Args{
		Image:   "gammaray-test-hello-world:1.0.0",
		LogFile: testLogFile,
		Path:    "",
	}).Run()
	if err != nil {
		panic(err)
	}
	info, error := os.Stat(testLogFile)
	if error != nil {
		t.Errorf("TestImageHelloWorld: Could not stat log file <%s>:\n%s", testLogFile, error)
	}
	log.Println("TestImageHelloWorld: log fileinfo:\n", info)

	if info.Size() == 0 {
		t.Errorf("TestImageHelloWorld: log size should not be 0!")
	}

}

func TestDefaults(t *testing.T) {
	expected := Args{
		Path:            "",
		Image:           "",
		LogFile:         ".gammaray.log",
		LogLevel:        "info",
		LogAsJSON:       false,
		OnlyInstalled:   false,
		OnlyPackageLock: false,
		OnlyYarnLock:    false,
	}

	if diff := cmp.Diff(*Defaults(), expected); diff != "" {
		t.Errorf("TestDefaults: error : (-got +want)\n%s", diff)
	}
}

func TestMainHelloWorld(t *testing.T) {
	defer cleanLogs()

	os.Args = []string{"./gammaray", "-path", "test_data/hello-world", "-log-file", testLogFile}

	main()

	info, error := os.Stat(testLogFile)
	if error != nil {
		t.Errorf("TestMainHelloWorld: Could not stat log file <%s>:\n%s", testLogFile, error)
	}
	log.Println("TestMainHelloWorld: log fileinfo:\n", info)

	if info.Size() == 0 {
		t.Errorf("TestMainHelloWorld: log size should not be 0!")
	}
}

func TestRunHelloWorld(t *testing.T) {
	defer cleanLogs()

	a := Args{Path: "test_data/hello-world"}

	err := a.Run()
	if err != nil {
		t.Error(err)
	}

}

func TestRunBadLogFile(t *testing.T) {
	defer cleanLogs()

	a := Args{Path: "test_data/hello-world", LogFile: "/dev/null"}

	err := a.Run()
	if err != nil {
		t.Error(err)
	}

}
