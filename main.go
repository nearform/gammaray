package main

import (
	"fmt"
	"log"
	"os"

	"github.com/jaffee/commandeer"
	"github.com/nearform/gammaray/analyzer"
	"github.com/nearform/gammaray/docker"
	"github.com/nearform/gammaray/vulnfetcher"
)

// Args CLI arguments
type Args struct {
	Path    string `help:"path to installed Node package (locally or inside the container, depending if 'image' is provided)"`
	Image   string `help:"analyze this docker image"`
	LogFile string `help:"in which file to put the detailed logs"`
}

// Defaults generate default CLI values
func Defaults() *Args {
	return &Args{
		Path:    "",
		Image:   "",
		LogFile: ".gammaray.log",
	}
}

func main() {
	err := commandeer.Run(Defaults())
	if err != nil {
		fmt.Println("Error:", err, "\n\nYou may want to check the logs (by default in <", Defaults().LogFile, ">) for more details")
		log.Println("Error:", err)
		os.Exit(1)
	}
}

// Run the program once CLI args are parsed
func (m *Args) Run() error {
	f, err := os.OpenFile(m.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v", err)
	} else {
		defer f.Close()
		log.SetOutput(f)
	}

	_, err = m.Analyze()
	return err
}

// Analyze the path or docker image for vulnerabilities
func (m *Args) Analyze() (vulnfetcher.VulnerabilityReport, error) {

	if m.Image == "" && m.Path != "" {
		return analyzer.Analyze(m.Path)
	} else if m.Image != "" {
		if m.Path != "" {
			fmt.Println("Will scan folder <", m.Path, "> from docker image <", m.Image, ">")
		} else {
			fmt.Println("Will scan docker image <", m.Image, ">")
		}

		return docker.ScanImage(m.Image, m.Path)
	} else if len(os.Args) > 1 {
		lastArg := os.Args[len(os.Args)-1]
		fmt.Println("⚠ Will use the last argument <", lastArg, "> as '-path' value.")
		return analyzer.Analyze(lastArg)
	}
	return nil, fmt.Errorf("you need to at least properly define a path or a docker image")
}
