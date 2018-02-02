package pathrunner

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// NodePackage represents a package.json (only the interesting fields)
type NodePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Walk inspects a folder looking for packages
func Walk(dir string) ([]NodePackage, error) {
	var packagesList []NodePackage

	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {

		if strings.HasSuffix(path, "package.json") {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				panic("Error reading " + path)
			}
			var packageFile NodePackage
			err = json.Unmarshal(data, &packageFile)
			if err != nil {
				panic("Error parsing data from " + path)
			}
			packagesList = append(packagesList, packageFile)
		}
		return nil
	})

	return packagesList, nil
}
