package pathrunner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nearform/gammaray/nodepackage"
)

// PackageLockRunner used is used as a Walker interface
type PathRunner struct {
	directory string
}

// ErrorContext tries to give enough context to the user for understanding what walker was impacted by this error
func (self PathRunner) ErrorContext(err error) string {
	return "While trying to walk the dependencies from the subdirectories of " + self.directory
}

// Walk inspects a folder looking for packages
func (self PathRunner) Walk(dir string) ([]nodepackage.NodePackage, error) {
	self.directory = dir
	var packagesList []nodepackage.NodePackage

	fileInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("<%s> is not a directory, make sure to put the proper path to your project", dir)
	}
	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {

		if strings.HasSuffix(path, "package.json") {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				panic("Error reading " + path)
			}
			var packageFile nodepackage.NodePackage
			err = json.Unmarshal(data, &packageFile)
			if err != nil {
				log.Println("Error parsing data from <", path, ">:\n", err)
				fmt.Println("⚠️ Will ignore invalid 'package.json' <", path, "> file")
			}
			packagesList = append(packagesList, packageFile)
		}
		return nil
	})

	return packagesList, nil
}
