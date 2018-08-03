package pathrunner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
			var packageFile NodePackage
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
