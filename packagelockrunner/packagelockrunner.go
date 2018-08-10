package packagelockrunner

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/nearform/gammaray/nodepackage"
	log "github.com/sirupsen/logrus"
)

type PackageLock struct {
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Dependencies PackageLockDependencies `json:"dependencies"`
}

type PackageLockDependencies map[string]PackageLockDependency

type PackageLockDependency struct {
	Version      string                  `json:"version"`
	Dependencies PackageLockDependencies `json:"dependencies"`
}

// PackageLockRunner used is used as a Walker interface
type PackageLockRunner struct {
	directory string
}

func unwrapDependencies(deps PackageLockDependencies) []nodepackage.NodePackage {
	var packageList []nodepackage.NodePackage

	for name, dep := range deps {
		packageList = append(packageList, nodepackage.NodePackage{Name: name, Version: dep.Version})
		if dep.Dependencies != nil {
			packageList = append(packageList, unwrapDependencies(dep.Dependencies)...)
		}
	}
	return packageList
}

// ErrorContext tries to give enough context to the user for understanding what walker was impacted by this error
func (self PackageLockRunner) ErrorContext(err error) string {
	return "While trying to walk the dependencies from the 'package-lock.json' of " + self.directory
}

// Walk inspects a folder's package-lock.json to get all the packages used
func (self PackageLockRunner) Walk(dir string) ([]nodepackage.NodePackage, error) {
	self.directory = dir
	log.Println("Starting Package-Lock Runner on <", dir, ">")
	var packageList []nodepackage.NodePackage

	fileInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("<%s> is not a directory, make sure to put the proper path to your project", dir)
	}
	packageLockFile := path.Join(dir, "package-lock.json")
	jsonFile, err := os.Open(packageLockFile)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	jsonParser := json.NewDecoder(jsonFile)

	var packageLock PackageLock
	err = jsonParser.Decode(&packageLock)
	if err != nil {
		return nil, err
	}
	packageDeps := unwrapDependencies(packageLock.Dependencies)

	packageList = append(packageList, nodepackage.NodePackage{Name: packageLock.Name, Version: packageLock.Version})
	packageList = append(packageList, packageDeps...)

	if len(packageList) == 1 {
		log.Println("Pakage-Lock Runner only found the project itself <", dir, ">")
	} else if len(packageList) == 0 {
		log.Println("Pakage-Lock Runner found no dependency in <", dir, ">")
	}
	return packageList, nil
}
