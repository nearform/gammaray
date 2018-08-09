package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jaffee/commandeer"
	"github.com/nearform/gammaray/analyzer"
	"github.com/nearform/gammaray/docker"
	"github.com/nearform/gammaray/nodepackage"
	"github.com/nearform/gammaray/packagelockrunner"
	"github.com/nearform/gammaray/pathrunner"
	"github.com/nearform/gammaray/vulnfetcher"
	"github.com/nearform/gammaray/yarnlockrunner"
	log "github.com/sirupsen/logrus"
)

// Args CLI arguments
type Args struct {
	Path            string `help:"path to installed Node package (locally or inside the container, depending if 'image' is provided)"`
	Image           string `help:"analyze this docker image"`
	LogFile         string `help:"in which file to put the detailed logs"`
	LogLevel        string `help:"minimal level that should be logged"`
	LogAsJSON       bool   `help:"detailed logs should be formated as JSON if true (default: false)"`
	OnlyInstalled   bool   `help:"force only installed module checking usage (default false: use it as the main strategy then use other fallbacks)"`
	OnlyPackageLock bool   `help:"force only <package-lock.json> usage (default false: use it as a fallback)"`
	OnlyYarnLock    bool   `help:"force only <yarn.lock> usage (default false: use it as a fallback)"`
}

// Defaults generate default CLI values
func Defaults() *Args {
	return &Args{
		Path:            "",
		Image:           "",
		LogFile:         ".gammaray.log",
		LogLevel:        "info",
		LogAsJSON:       false,
		OnlyInstalled:   false,
		OnlyPackageLock: false,
		OnlyYarnLock:    false,
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

func (m *Args) getLogLevel() log.Level {

	switch strings.ToLower(strings.TrimSpace(m.LogLevel)) {
	case "panic":
		return log.PanicLevel
	case "fatal":
		return log.FatalLevel
	case "error":
		return log.ErrorLevel
	case "warn":
		return log.WarnLevel
	case "info":
		return log.InfoLevel
	case "debug":
		return log.DebugLevel
	default:
		return log.InfoLevel
	}
}

// Run the program once CLI args are parsed
func (m *Args) Run() error {
	if m.LogAsJSON == true {
		log.SetFormatter(&log.JSONFormatter{})
	}
	log.SetLevel(m.getLogLevel())
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
	var walkers []nodepackage.Walker
	if m.OnlyPackageLock == true {
		walkers = []nodepackage.Walker{
			pathrunner.PathRunner{},
		}
	} else if m.OnlyPackageLock == true {
		walkers = []nodepackage.Walker{
			packagelockrunner.PackageLockRunner{},
		}
	} else if m.OnlyYarnLock == true {
		walkers = []nodepackage.Walker{
			yarnlockrunner.YarnLockRunner{},
		}
	}
	if m.Image == "" && m.Path != "" {
		return analyzer.Analyze(m.Path, walkers...)
	} else if m.Image != "" {
		if m.Path != "" {
			fmt.Println("🔍 Will scan folder <", m.Path, "> from docker image <", m.Image, ">")
		} else {
			fmt.Println("🔍 Will scan docker image <", m.Image, ">")
		}

		return docker.ScanImage(m.Image, m.Path, walkers...)
	} else if len(os.Args) > 1 {
		lastArg := os.Args[len(os.Args)-1]
		fmt.Println("⚠ Will use the last argument <", lastArg, "> as '-path' value.")
		return analyzer.Analyze(lastArg, walkers...)
	}
	return nil, fmt.Errorf("you need to at least properly define a path or a docker image")
}
