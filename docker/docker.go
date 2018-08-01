package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	unarr "github.com/gen2brain/go-unarr"
	"github.com/nearform/gammaray/analyzer"
	"github.com/nearform/gammaray/vulnfetcher"
)

type DockerImageFiles struct {
	Layers []string `json:"Layers"`
	Config string   `json:"Config"`
}

type DockerConfig struct {
	ContainerConfig DockerContainerConfig `json:"container_config"`
}

type DockerContainerConfig struct {
	WorkingDir string `json:"WorkingDir"`
}

func Cleanup(path string) {
	fmt.Println("Cleanup temporary docker files")
	err := os.RemoveAll(path)
	if err != nil {
		log.Println("⚠️ Could not remove temporary docker image extraction folder <", path, ">:\n", err)
	}
}

// ScanImage extracts an image and analyzes its layers
func ScanImage(imageName string, projectPath string) (vulnfetcher.VulnerabilityReport, error) {
	ctx := context.Background()
	cli, err := docker.NewEnvClient()
	if err != nil {
		log.Println("Could not connect to docker")
		return nil, err
	}

	reader, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		log.Println("Cannot pull image <", imageName, ">, will try to use a local version")
		// return nil, err
	} else {
		// io.Copy(os.Stdout, reader) //JSONLD pull logs
		_, err = ioutil.ReadAll(reader)
		if err != nil {
			log.Println("Could not pull image <", imageName, ">")
			return nil, err
		}
	}

	response, err := cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		log.Println("Could not save image <", imageName, ">")
		return nil, err
	}
	imageFolder := path.Join(os.TempDir(), strconv.FormatInt(time.Now().Unix(), 10))

	defer Cleanup(imageFolder)

	tarFile := imageFolder + ".tar"

	f, err := os.Create(tarFile)
	if err != nil {
		log.Println("Could create image <", imageName, "> tar <", tarFile, ">")
		return nil, err
	}
	io.Copy(f, response)

	a, err := unarr.NewArchive(tarFile)
	if err != nil {
		log.Println("Could not open docker image <", tarFile, ">")
		return nil, err
	}
	err = a.Extract(imageFolder)
	if err != nil {
		log.Println("Could not extract docker image <", tarFile, ">")
		return nil, err
	}

	fmt.Println("Docker image <", imageName, "> decompressed in <", imageFolder, ">")

	manifestFile, err := ioutil.ReadFile(path.Join(imageFolder, "manifest.json"))
	if err != nil {
		log.Println("Could not open docker image manifest!")
		return nil, err
	}
	var manifests []DockerImageFiles
	err = json.Unmarshal(manifestFile, &manifests)
	if err != nil {
		log.Println("Could not unmarshal docker image manifest!")
		return nil, err
	}
	if len(manifests) < 1 {
		return nil, fmt.Errorf("docker image '%s' manifest.json does not contain enough data", imageName)
	}
	if len(manifests) > 1 {
		log.Println("⚠️ Will only analyze what is described by the first entry of the manifest.json of image <", imageName, "> : for more details, check ", path.Join(imageFolder, "manifest.json"))
	}

	manifest := manifests[0]
	fmt.Println("Decompressing docker image layers...")

	snapshotPath := path.Join(imageFolder, "snapshot")

	for _, layerFile := range manifest.Layers {
		layerPath := path.Join(imageFolder, layerFile)
		fmt.Println("Decompressing layer <", layerPath, ">")

		a, err := unarr.NewArchive(layerPath)
		if err != nil {
			log.Println("Could not read layer <", layerPath, ">!")
			return nil, err
		}
		err = a.Extract(snapshotPath)
		if err != nil {
			log.Println("Could not extract layer <", layerPath, ">!")
			return nil, err
		}
	}

	configFile, err := ioutil.ReadFile(path.Join(imageFolder, manifest.Config))
	if err != nil {
		log.Println("Could not open docker image configuration!")
		return nil, err
	}

	fmt.Println("Read docker image configuration...")
	var config DockerConfig
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Println("Could not unmarshal docker image configuration!")
		return nil, err
	}
	imageProjectPath := config.ContainerConfig.WorkingDir
	if projectPath != "" {
		imageProjectPath = projectPath
	}

	fmt.Println("Analyze image stored in <", imageProjectPath, ">")
	return analyzer.Analyze(path.Join(imageFolder, "snapshot", imageProjectPath))
}
