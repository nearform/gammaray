package docker

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"testing"

	docker "github.com/docker/docker/client"
	"github.com/google/go-cmp/cmp"
)

func TestCleanupInvalidFolder(t *testing.T) {
	Cleanup("invalid-folder")
}

func TestScanImageHelloWorld(t *testing.T) {
	vulns, err := ScanImage("gammaray-test-hello-world:1.0.0", "")
	if err != nil {
		panic(err)
	}
	numVulns := 0
	for provider, vulnList := range vulns {
		numVulns += len(vulnList)
		log.Print(provider, "> ", len(vulnList), " vulnerabilities:\n", vulnList)
	}
	if diff := cmp.Diff(numVulns, 0); diff != "" {
		t.Errorf("TestHelloWorld: vulnerabilities : (-got +want)\n%s", diff)
	}
}

func TestScanImageInsecureProject(t *testing.T) {
	vulns, err := ScanImage("gammaray-test-insecure-project:1.0.0", "")
	if err != nil {
		panic(err)
	}
	for provider, vulnList := range vulns {
		providerVulns := len(vulnList)
		log.Print(provider, "> ", providerVulns, " vulnerabilities:\n", vulnList)
		// both OSSIndex and NodeSWG report bassmaster-1.0.0 and its dep hoek-1.5.2
		if diff := cmp.Diff(providerVulns, 2); diff != "" {
			t.Errorf("TestInsecureProject: %s vulnerabilities : (-got +want)\n%s", provider, diff)
		}
	}
}

func TestScanImageNotExisting(t *testing.T) {
	_, err := ScanImage("gammaray-test-this-one-should not-exist", "")
	if err == nil {
		panic(fmt.Errorf("'gammaray-test-this-one-should not-exist' should not exist and create an error"))
	}
}

func TestPullImageIfNecessaryOfficialNodeAlpine(t *testing.T) {
	ctx := context.Background()
	cli, err := docker.NewEnvClient()
	if err != nil {
		t.Errorf("TestPullImageIfNecessaryOfficialNodeAlpine: Could not connect to docker: %s \n", err.Error())
	}
	err = pullImageIfNecessary(ctx, "node:latest", cli)
	if err == nil {
		return
	}
	if err.Error() != "" {
		t.Errorf("TestPullImageIfNecessaryOfficialNodeAlpine: %s \n", err.Error())
	}
}

func TestExportImageLocallyInvalidImage(t *testing.T) {
	ctx := context.Background()
	cli, err := docker.NewEnvClient()
	if err != nil {
		t.Errorf("TestExportImageLocallyInvalidImage: Could not connect to docker: %s \n", err.Error())
	}
	err = exportImageLocally(ctx, "🐭 Invalid test image name 😉", "", cli)
	if err == nil {
		t.Error("TestExportImageLocallyInvalidImage should make an error due to the image name being invalid")
		return
	}
	if diff := cmp.Diff(err.Error(), "Error response from daemon: invalid reference format: repository name must be lowercase"); diff != "" {
		t.Errorf("TestExportImageLocallyInvalidImage: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestExportImageArchiveInvalidTarFile(t *testing.T) {
	err := extractImageArchive("/dev/null/invalid.tar", os.TempDir(), "image with invalid tar archive for tests")
	if err == nil {
		t.Error("TestExportImageArchiveInvalidTarFile should make an error due to the image destination folder being invalid")
		return
	}
	if diff := cmp.Diff(err.Error(), "unarr: File not found"); diff != "" {
		t.Errorf("TestExportImageArchiveInvalidTarFile: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestExportImageArchiveInvalidImageFolder(t *testing.T) {
	err := extractImageArchive("./test_data/valid.tar", "/dev/null/invalid", "image with invalid destination folder")
	if err == nil {
		t.Error("TestExportImageArchiveInvalidImageFolder should make an error due to the image destination folder being invalid")
		return
	}
	if diff := cmp.Diff(err.Error(), "open /dev/null/invalid/0297acce13fc12b22bf2caedde2829ab4847f5fe4ae6ba90073f90e7e26433a0/VERSION: not a directory"); diff != "" {
		t.Errorf("TestExportImageArchiveInvalidImageFolder: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestExportImageArchiveValidImageFolder(t *testing.T) {
	extractPath := path.Join(os.TempDir(), "gammaray-test-TestExportImageArchiveValidImageFolder")
	defer Cleanup(extractPath)
	err := extractImageArchive("./test_data/valid.tar", extractPath, "valid image")
	if err != nil {
		t.Error("TestExportImageArchiveValidImageFolder should not make an error:" + err.Error())
		return
	}
}

func TestReadManifestNoManifest(t *testing.T) {
	_, err := readManifest("./test_data", "no manifest image")
	if err == nil {
		t.Error("TestReadManifestNoManifest should make an error due to the lack of manifest in folder")
		return
	}
	if diff := cmp.Diff(err.Error(), "open test_data/manifest.json: no such file or directory"); diff != "" {
		t.Errorf("TestReadManifestNoManifest: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestReadManifestInvalidManifest(t *testing.T) {
	_, err := readManifest("./test_data/invalid-manifest", "invalid manifest image")
	if err == nil {
		t.Error("TestReadManifestInvalidManifest should make an error due to the invlid manifest content")
		return
	}
	if diff := cmp.Diff(err.Error(), "json: cannot unmarshal object into Go value of type []docker.DockerImageFiles"); diff != "" {
		t.Errorf("TestReadManifestInvalidManifest: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestExtractLayersNoLayer(t *testing.T) {
	layers := []string{"not-existing"}
	manifest := DockerImageFiles{
		Layers: layers,
	}
	extractPath := path.Join(os.TempDir(), "gammaray-test-TestExtractLayersNoLayer")
	err := extractLayers("./test_data", extractPath, &manifest)
	defer Cleanup(extractPath)
	if err == nil {
		t.Error("TestExtractLayersNoLayer should make an error due to the lack of layer described by the manifest")
		return
	}
	if diff := cmp.Diff(err.Error(), "unarr: File not found"); diff != "" {
		t.Errorf("TestExtractLayersNoLayer: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestExtractLayersInvalidLayer(t *testing.T) {
	layers := []string{"invalid-layer.tar"}
	manifest := DockerImageFiles{
		Layers: layers,
	}
	extractPath := path.Join(os.TempDir(), "gammaray-test-TestExtractLayersInvalidLayer")
	err := extractLayers("./test_data/invalid-layers", extractPath, &manifest)
	defer Cleanup(extractPath)
	if err == nil {
		t.Error("TestExtractLayersInvalidLayer should make an error due to the layer archive being dummy")
		return
	}
	if diff := cmp.Diff(err.Error(), "unarr: No valid RAR, ZIP, 7Z or TAR archive"); diff != "" {
		t.Errorf("TestExtractLayersInvalidLayer: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestReadManifestNoImageConfig(t *testing.T) {
	manifest := DockerImageFiles{Config: "not-existing-config.json"}

	_, err := readImageConfig("./test_data", &manifest)
	if err == nil {
		t.Error("TestReadManifestNoImageConfig should make an error due to the lack of manifest in folder")
		return
	}
	if diff := cmp.Diff(err.Error(), "open test_data/not-existing-config.json: no such file or directory"); diff != "" {
		t.Errorf("TestReadManifestNoImageConfig: expected a different error : (-got +want)\n%s", diff)
	}
}

func TestReadManifestInvalidConfig(t *testing.T) {
	manifest := DockerImageFiles{Config: "config.json"}

	_, err := readImageConfig("./test_data/invalid-config", &manifest)
	if err == nil {
		t.Error("TestReadManifestInvalidConfig should make an error due to the invalid manifest content")
		return
	}
	if diff := cmp.Diff(err.Error(), "json: cannot unmarshal array into Go value of type docker.DockerConfig"); diff != "" {
		t.Errorf("TestReadManifestInvalidConfig: expected a different error : (-got +want)\n%s", diff)
	}
}
