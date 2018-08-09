package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	unarr "github.com/gen2brain/go-unarr"
	"github.com/nearform/gammaray/analyzer"
	"github.com/nearform/gammaray/nodepackage"
	"github.com/nearform/gammaray/vulnfetcher"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
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
	log.Infoln("Cleanup temporary docker files at <", path, ">")
	err := os.RemoveAll(path)
	if err != nil {
		log.Warnln("⚠️ Could not remove temporary docker file <", path, ">:\n", err)
	}
}

func pullImageIfNecessary(ctx context.Context, imageName string, cli *docker.Client) error {
	reader, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		log.Warnln("⚠️ Cannot pull image <", imageName, ">, will try to use a local version")
		return nil
	}

	// io.Copy(os.Stdout, reader) //JSONLD pull logs
	_, err = ioutil.ReadAll(reader)
	if err != nil {
		log.Errorln("Could not pull image <", imageName, ">")
		return err
	}

	return nil
}

func extractImageArchive(tarFile string, imageFolder string, imageName string) error {
	a, err := unarr.NewArchive(tarFile)
	if err != nil {
		log.Errorln("Could not open docker image <", tarFile, ">")
		return err
	}
	err = a.Extract(imageFolder)
	if err != nil {
		log.Errorln("Could not extract docker image <", tarFile, ">")
		return err
	}

	fmt.Println("🗃 Docker image <", imageName, "> decompressed in <", imageFolder, ">")
	return nil
}

func exportImageLocally(ctx context.Context, imageName string, imageFolder string, cli *docker.Client) error {
	response, err := cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		log.Errorln("Could not save image <", imageName, ">")
		return err
	}

	tarFile := imageFolder + ".tar"

	f, err := os.Create(tarFile)
	if err != nil {
		log.Errorln("Could not create image <", imageName, "> tar <", tarFile, ">")
		return err
	}
	io.Copy(f, response)
	defer Cleanup(tarFile)

	return extractImageArchive(tarFile, imageFolder, imageName)
}

func readManifest(imageFolder string, imageName string) (*DockerImageFiles, error) {
	manifestFile, err := ioutil.ReadFile(path.Join(imageFolder, "manifest.json"))
	if err != nil {
		log.Errorln("Could not open docker image manifest!")
		return nil, err
	}
	var manifests []DockerImageFiles
	err = json.Unmarshal(manifestFile, &manifests)
	if err != nil {
		log.Errorln("Could not unmarshal docker image manifest!")
		return nil, err
	}
	if len(manifests) < 1 {
		return nil, fmt.Errorf("docker image '%s' manifest.json does not contain enough data", imageName)
	}
	if len(manifests) > 1 {
		log.Warnln("⚠️ Will only analyze what is described by the first entry of the manifest.json of image <", imageName, "> : for more details, check ", path.Join(imageFolder, "manifest.json"))
	}

	return &manifests[0], nil
}

func extractLayers(imageFolder string, snapshotPath string, manifest *DockerImageFiles) error {
	for _, layerFile := range manifest.Layers {
		layerPath := path.Join(imageFolder, layerFile)
		log.Debugln("🗃 Decompressing layer <", layerPath, ">")

		a, err := unarr.NewArchive(layerPath)
		if err != nil {
			log.Errorln("🗃 Could not read layer <", layerPath, ">!")
			return err
		}
		err = a.Extract(snapshotPath)
		if err != nil {
			log.Errorln("Could not extract layer <", layerPath, ">!")
			return err
		}
	}
	return nil
}

func readImageConfig(imageFolder string, manifest *DockerImageFiles) (*DockerConfig, error) {
	configFile, err := ioutil.ReadFile(path.Join(imageFolder, manifest.Config))
	if err != nil {
		log.Errorln("Could not open docker image configuration!")
		return nil, err
	}

	log.Infoln("🗃 Read docker image configuration...")
	var config DockerConfig
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Errorln("Could not unmarshal docker image configuration!")
		return nil, err
	}
	return &config, nil
}

// ScanImage extracts an image and analyzes its layers
func ScanImage(imageName string, projectPath string, walkers ...nodepackage.Walker) (vulnfetcher.VulnerabilityReport, error) {
	ctx := context.Background()
	cli, err := docker.NewEnvClient()
	if err != nil {
		log.Errorln("Could not connect to docker")
		return nil, err
	}

	err = pullImageIfNecessary(ctx, imageName, cli)
	if err != nil {
		return nil, err
	}

	imageFolder := path.Join(os.TempDir(), strconv.FormatInt(time.Now().Unix(), 10))
	exportImageLocally(ctx, imageName, imageFolder, cli)
	if err != nil {
		return nil, err
	}
	defer Cleanup(imageFolder)

	manifest, err := readManifest(imageFolder, imageName)
	if err != nil {
		return nil, err
	}
	log.Infoln("🗃 Decompressing docker image layers...")

	snapshotPath := path.Join(imageFolder, "snapshot")

	err = extractLayers(imageFolder, snapshotPath, manifest)
	if err != nil {
		return nil, err
	}

	config, err := readImageConfig(imageFolder, manifest)
	if err != nil {
		return nil, err
	}
	imageProjectPath := config.ContainerConfig.WorkingDir
	if projectPath != "" {
		log.Infoln("🗃 Using provided -path <", projectPath, "> instead of docker's working directory <", config.ContainerConfig.WorkingDir, ">")
		imageProjectPath = projectPath
	}

	fmt.Println("🗃 Analyze package stored at <", imageProjectPath, "> in image <", imageName, ">...")
	return analyzer.Analyze(path.Join(imageFolder, "snapshot", imageProjectPath), walkers...)
}
