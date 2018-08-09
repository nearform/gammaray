package yarnlockrunner

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/nearform/gammaray/nodepackage"
	"github.com/nearform/gammaray/yarnlockparser"
)

// PackageLockRunner used is used as a Walker interface
type YarnLockRunner struct {
	directory string
}

// ErrorContext tries to give enough context to the user for understanding what walker was impacted by this error
func (self YarnLockRunner) ErrorContext(err error) string {
	return "While trying to walk the dependencies from the 'yarn.lock' of " + self.directory
}

// Walk inspects a folder's package-lock.json to get all the packages used
func (self YarnLockRunner) Walk(dir string) ([]nodepackage.NodePackage, error) {
	fileInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("<%s> is not a directory, make sure to put the proper path to your project", dir)
	}
	yarnLockFile := path.Join(dir, "yarn.lock")
	content, err := ioutil.ReadFile(yarnLockFile)
	if err != nil {
		return nil, err
	}
	return yarnlockparser.ParseYarnLock(string(content))
}
