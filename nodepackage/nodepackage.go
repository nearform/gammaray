package nodepackage

// NodePackage represents a package.json (only the interesting fields)
type NodePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Walker interface is used to allow multiple backends using this interface to find out dependencies for a given dir
type Walker interface {
	Walk(dir string) ([]NodePackage, error)
	ErrorContext(error) string
}
