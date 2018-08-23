package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/copy"
	"github.com/containers/image/directory"
	"github.com/containers/image/docker"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/transports"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type repoDescriptor struct {
	RootReference  types.ImageReference
	TagsReferences []types.ImageReference
	Context        *types.SystemContext
}

type registrySyncCfg struct {
	Images      map[string][]string
	Credentials types.DockerAuthConfig
	TLSVerify   bool   `yaml:"tls-verify"`
	CertDir     string `yaml:"cert-dir"`
}

type sourceCfg map[string]registrySyncCfg

// Generates a config structure from a YAML file.
func newSourceConfig(yamlFile string) (cfg sourceCfg, err error) {
	err = yamlUnmarshal(yamlFile, &cfg)
	return
}

// Checks if a given transport is supported by the sync operation.
func isValidTransport(transport types.ImageTransport) bool {
	switch transport {
	case docker.Transport:
		return true
	case directory.Transport:
		return true
	}

	return false
}

// Parses a complete path (including the transport name) and returns an
// ImageReference. The transport checked to be supported by sync.
func parseInputPath(path string) (types.ImageReference, error) {
	path = strings.TrimRight(path, "/")
	ref, err := alltransports.ParseImageName(path)
	if err != nil {
		return nil, fmt.Errorf("Cannot obtain a valid image reference from '%s': %v", path, err)
	}
	valid := isValidTransport(ref.Transport())
	if !valid {
		return nil, fmt.Errorf("Invalid transport")
	}

	return ref, nil
}

// Given a tranport and an image name (without the transport), returns an
// ImageReference.
func getImageReference(transport types.ImageTransport, imgName string) (types.ImageReference, error) {
	ref, err := transport.ParseReference(imgName)
	if err != nil {
		return nil, fmt.Errorf("Cannot obtain a valid image reference from '%s': %v", imgName, err)
	}

	return ref, nil
}

// Builds the final destination of the image.
// Eg: given the destination `docker://my-registry.local.lan`
// and src `docker://registry.example.com/busybox:stable`
// the final destination is going to be:
// docker://my-registry.local.lan/registry.example.com/busybox:stable
func buildFinalDestination(rootSrc, srcRef, baseDest types.ImageReference) (types.ImageReference, error) {
	var destTransport types.ImageTransport
	var path string

	switch srcRef.Transport() {
	case docker.Transport:
		// docker -> dir or docker -> docker
		path = srcRef.DockerReference().Name()
	case directory.Transport:
		// dir -> docker (we don't allow `dir` -> `dir` sync operations)
		path = strings.TrimPrefix(srcRef.PolicyConfigurationIdentity(), rootSrc.PolicyConfigurationIdentity())
	}

	destTransport = baseDest.Transport()
	var finalDest string

	switch baseDest.Transport() {
	case docker.Transport:
		finalDest = baseDest.StringWithinTransport() + "/" + path
	case directory.Transport:
		finalDest = baseDest.StringWithinTransport() + path
		tgtDir := finalDest
		logrus.Infof("Creating dir path: %s", tgtDir)
		// the final directory holding the image must exist otherwise
		// the directory ImageReference instance won't be created
		if _, err := os.Stat(tgtDir); err != nil {
			if os.IsNotExist(err) {
				if err := os.MkdirAll(tgtDir, 0755); err != nil {
					return nil, fmt.Errorf("Error creating directory for image %s: %v",
						tgtDir,
						err)
				}
			} else {
				return nil, fmt.Errorf("Error while checking existence of directory %s: %v",
					tgtDir,
					err)
			}
		}
	}
	logrus.Debugf("final destination: %s", finalDest)

	destRef, err := getImageReference(destTransport, finalDest)
	if err != nil {
		return nil, err
	}

	return destRef, nil
}

// Retrieves all the tags associated to an image stored on a container registry.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, imgRef types.ImageReference) (tags []string, retErr error) {
	img, err := imgRef.NewImage(ctx, sysCtx)
	if err != nil {
		return tags, err
	}
	defer func() {
		if err := img.Close(); err != nil {
			retErr = errors.Wrapf(retErr, fmt.Sprintf("(could not close image: %v) ", err))
		}
	}()
	if dockerImg, ok := img.(*docker.Image); ok {
		logrus.WithFields(logrus.Fields{
			"image": dockerImg.SourceRefFullName(),
		}).Info("Getting tags")
		tags, retErr = dockerImg.GetRepositoryTags(context.Background())
		if retErr != nil {
			// some registries may decide to block the "list all tags" endpoint
			// gracefully allow the inspect to continue in this case. Currently
			// the IBM Bluemix container registry has this restriction.
			if !strings.Contains(retErr.Error(), "401") {
				return tags, fmt.Errorf("Error determining repository tags: %v", retErr)
			}
			logrus.Warn("Registry disallows tag list retrieval; skipping")
		}
	}

	return tags, retErr
}

// Checks if an image name includes a tag.
func isTagSpecified(imageName string) (bool, error) {
	imageName = strings.TrimPrefix(imageName, "//")
	normNamed, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return false, err
	}

	tagged := !reference.IsNameOnly(normNamed)
	logrus.WithFields(logrus.Fields{
		"image":  imageName,
		"tagged": tagged,
	}).Info("check image tag presence")
	return tagged, nil
}

// Given an image reference on a container registry, returns a list of image
// references, one for each of the tags available for the given input image.
func imagesToCopyFromRegistry(srcRef types.ImageReference, src string, sourceCtx *types.SystemContext) (sourceReferences []types.ImageReference, retErr error) {
	tags, err := getImageTags(context.Background(), sourceCtx, srcRef)
	if err != nil {
		return []types.ImageReference{},
			fmt.Errorf(
				"Error while retrieving available tags of %s: %v",
				src,
				err)
	}
	for _, tag := range tags {
		imageAndTag := fmt.Sprintf("%s:%s", src, tag)
		ref, err := getImageReference(docker.Transport, imageAndTag)
		if err != nil {
			return []types.ImageReference{},
				fmt.Errorf("Error while building reference of %s: %v",
					imageAndTag,
					err)
		}
		sourceReferences = append(sourceReferences, ref)
	}
	return sourceReferences, retErr
}

// Given an image reference as a local directory, returns all the image
// references available at the given path.
func imagesToCopyFromDir(srcRef types.ImageReference) (sourceReferences []types.ImageReference, retErr error) {
	err := filepath.Walk(srcRef.StringWithinTransport(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "manifest.json" {
			ref, err := getImageReference(directory.Transport, fmt.Sprintf("%s", filepath.Dir(path)))
			if err != nil {
				return fmt.Errorf(
					"Error while creating image referenced for path %s: %v",
					filepath.Dir(path),
					err)
			}
			sourceReferences = append(sourceReferences, ref)
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		return []types.ImageReference{},
			fmt.Errorf("error walking the path %q: %v", srcRef.StringWithinTransport(), err)
	}

	return
}

// Runs the sync from a single SOURCE path.
func syncFromPath(source string, destRef types.ImageReference, sourceCtx *types.SystemContext) (repoDesc repoDescriptor, retErr error) {
	srcRef, err := parseInputPath(source)
	if err != nil {
		return repoDesc, fmt.Errorf("Error while parsing source: %v", err)
	}
	repoDesc.RootReference = srcRef

	if srcRef.Transport() == directory.Transport && destRef.Transport() == directory.Transport {
		return repoDesc,
			fmt.Errorf("sync from 'dir:' to 'dir:' not implemented, use something like rsync instead")
	}

	repoDesc.Context = sourceCtx

	source = strings.TrimPrefix(source, srcRef.Transport().Name()+":")
	switch srcRef.Transport() {
	case docker.Transport:
		imageTagged, err := isTagSpecified(source)
		if err != nil {
			return repoDesc, err
		}
		if imageTagged {
			repoDesc.TagsReferences = append(repoDesc.TagsReferences, srcRef)
			break
		}
		repoDesc.TagsReferences, retErr = imagesToCopyFromRegistry(srcRef, source, sourceCtx)
	case directory.Transport:
		repoDesc.TagsReferences, retErr = imagesToCopyFromDir(srcRef)
	}

	return
}

// Runs the sync from a YAML file.
func syncFromYaml(yamlFile string, sourceCtx *types.SystemContext) (repoDescList []repoDescriptor, err error) {
	cfg, err := newSourceConfig(yamlFile)
	if err != nil {
		return
	}

	for server, serverCfg := range cfg {
		logrus.WithFields(logrus.Fields{
			"server": server,
		}).Info("Processing all images from server")

		for imageName, tags := range serverCfg.Images {
			repoName := "//" + filepath.Join(server, imageName)
			logrus.WithFields(logrus.Fields{
				"repo": repoName,
			}).Info("Processing repo")

			serverCtx := sourceCtx

			// override ctx with per-server options
			serverCtx.DockerCertPath = serverCfg.CertDir
			serverCtx.DockerDaemonCertPath = serverCfg.CertDir
			serverCtx.DockerDaemonInsecureSkipTLSVerify = !serverCfg.TLSVerify
			serverCtx.DockerInsecureSkipTLSVerify = !serverCfg.TLSVerify
			serverCtx.DockerAuthConfig = &serverCfg.Credentials

			var sourceReferences []types.ImageReference
			for _, tag := range tags {
				source := fmt.Sprintf("%s:%s", repoName, tag)

				imageRef, err := docker.ParseReference(source)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"tag": source,
					}).Error("Error processing tag, skipping")
					logrus.Errorf("Error getting image reference: %s", err)
					continue
				}
				sourceReferences = append(sourceReferences, imageRef)
			}

			if len(tags) == 0 {
				imageRef, err := docker.ParseReference(repoName)

				if err != nil {
					logrus.WithFields(logrus.Fields{
						"repo": repoName,
					}).Error("Error processing repo, skipping")
					logrus.Error(err)
					continue
				}
				logrus.WithFields(logrus.Fields{
					"repo": repoName,
				}).Info("No tags given, querying registry")

				sourceReferences, err = imagesToCopyFromRegistry(imageRef, repoName, serverCtx)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"repo": repoName,
					}).Error("Error processing repo, skipping")
					logrus.Error(err)
					continue
				}
			}

			repoDescList = append(repoDescList, repoDescriptor{
				RootReference:  nil,
				TagsReferences: sourceReferences,
				Context:        serverCtx})
		}
	}

	return
}

func syncHandler(c *cli.Context) (retErr error) {
	if len(c.Args()) != 2 {
		cli.ShowCommandHelp(c, "sync")
		return errors.New("Exactly one argument expected")
	}

	policyContext, err := getPolicyContext(c)
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %v", err)
	}
	defer policyContext.Destroy()

	destRef, err := parseInputPath(c.Args()[1])
	if err != nil {
		return fmt.Errorf("Error while parsing destination: %v", err)
	}
	destinationCtx, err := contextFromGlobalOptions(c, "dest-")
	if err != nil {
		return err
	}

	signBy := c.String("sign-by")
	removeSignatures := c.Bool("remove-signatures")

	sourceCtx, err := contextFromGlobalOptions(c, "src-")
	if err != nil {
		return err
	}
	sourceArg := c.Args()[0]

	var srcRepoList []repoDescriptor

	if c.IsSet("source-yaml") {
		srcRepoList, err = syncFromYaml(sourceArg, sourceCtx)
		if err != nil {
			return err
		}
	} else {
		srcRepo, err := syncFromPath(sourceArg, destRef, sourceCtx)
		if err != nil {
			return err
		}
		srcRepoList = append(srcRepoList, srcRepo)
	}

	for _, srcRepo := range srcRepoList {
		options := copy.Options{
			RemoveSignatures: removeSignatures,
			SignBy:           signBy,
			ReportWriter:     os.Stdout,
			DestinationCtx:   destinationCtx,
			SourceCtx:        srcRepo.Context,
		}

		for counter, ref := range srcRepo.TagsReferences {
			logrus.WithFields(logrus.Fields{
				"from": transports.ImageName(ref),
				"to":   transports.ImageName(destRef),
			}).Infof("Processing tag %d/%d", counter+1, len(srcRepo.TagsReferences))

			destRef, err := buildFinalDestination(srcRepo.RootReference, ref, destRef)
			if err != nil {
				return err
			}

			logrus.Debug("Copy started")
			err = copy.Image(context.Background(), policyContext, destRef, ref, &options)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"repo": transports.ImageName(ref),
				}).Error("Error copying tag, skipping")
				logrus.Debug(err)
				continue
			}
		}
	}

	return nil
}

var syncCmd = cli.Command{
	Name:  "sync",
	Usage: "Sync one or more images from one location to another",
	Description: fmt.Sprint(`

	Copy all the images from SOURCE to DESTINATION.

	Useful to keep in sync a local container registry mirror. Can be used
	to populate also registries running inside of air-gapped environments.

	SOURCE can be either a repository hosted on a container registry
	(eg: docker://registry.example.com/busybox) or a local directory
	(eg: dir:/media/usb/).

	If --source-yaml is specified, then SOURCE points to a YAML file with
	a list of source images from different container registries
	(local directories are not supported).

	When the source location is a container registry and no tags are specified,
	skopeo sync will copy all the tags associated to the source image.

	DESTINATION can be either a container registry
	(eg: docker://my-registry.local.lan) or a local directory
	(eg: dir:/media/usb).

	When DESTINATION is a local directory, one directory per 'image:tag' is going
	to be created.
	`),
	ArgsUsage: "[--source-yaml] SOURCE DESTINATION",
	Action:    syncHandler,
	// FIXME: Do we need to namespace the GPG aspect?
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "authfile",
			Usage: "path of the authentication file. Default is ${XDG_RUNTIME_DIR}/containers/auth.json",
		},
		cli.BoolFlag{
			Name:  "remove-signatures",
			Usage: "Do not copy signatures from SOURCE images",
		},
		cli.StringFlag{
			Name:  "sign-by",
			Usage: "Sign the image using a GPG key with the specified `FINGERPRINT`",
		},
		cli.BoolFlag{
			Name:  "source-yaml",
			Usage: "Interpret SOURCE as a YAML file with a list of images from different container regitries",
		},
		cli.StringFlag{
			Name:  "src-creds, screds",
			Value: "",
			Usage: "Use `USERNAME[:PASSWORD]` for accessing the source registry",
		},
		cli.StringFlag{
			Name:  "dest-creds, dcreds",
			Value: "",
			Usage: "Use `USERNAME[:PASSWORD]` for accessing the destination registry",
		},
		cli.StringFlag{
			Name:  "src-cert-dir",
			Value: "",
			Usage: "use certificates at `PATH` (*.crt, *.cert, *.key) to connect to the source registry or daemon",
		},
		cli.BoolTFlag{
			Name:  "src-tls-verify",
			Usage: "require HTTPS and verify certificates when talking to the container source registry or daemon (defaults to true)",
		},
		cli.StringFlag{
			Name:  "dest-cert-dir",
			Value: "",
			Usage: "use certificates at `PATH` (*.crt, *.cert, *.key) to connect to the destination registry or daemon",
		},
		cli.BoolTFlag{
			Name:  "dest-tls-verify",
			Usage: "require HTTPS and verify certificates when talking to the container destination registry or daemon (defaults to true)",
		},
	},
}
