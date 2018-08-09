package pathrunner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/nearform/gammaray/nodepackage"
	log "github.com/sirupsen/logrus"
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
	log.Println("Starting Path Runner on <", dir, ">")
	self.directory = dir
	var packageList []nodepackage.NodePackage

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
				log.Warnln("Error parsing data from <", path, ">:\n", err)
				fmt.Println("⚠️ Will ignore invalid 'package.json' <", path, "> file")
			}
			packageList = append(packageList, packageFile)
		}
		return nil
	})
	if len(packageList) == 1 {
		log.Infoln("Path Runner only found the project itself <", dir, ">")
	} else if len(packageList) == 0 {
		log.Warnln("Path Runner found no dependency in <", dir, ">")
	}
	return packageList, nil
}
