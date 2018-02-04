package docker

import (
	"context"
	"io"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	docker "github.com/docker/docker/client"
	"github.com/mholt/archiver"
)

func ScanImage(imageName string) error {
	cli, err := docker.NewEnvClient()

	spew.Dump(err)
	response, err := cli.ImageSave(context.Background(), []string{imageName})
	imageFolder := path.Join(os.TempDir(), strconv.FormatInt(time.Now().Unix(), 10))
	targzFile := imageFolder + ".tar.gz"
	spew.Dump(targzFile)
	f, err := os.Create(targzFile)
	io.Copy(f, response)
	archiver.TarGz.Open(targzFile, imageFolder)
	return nil
}
