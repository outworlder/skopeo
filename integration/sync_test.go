package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-check/check"
)

func init() {
	check.Suite(&SyncSuite{})
}

type SyncSuite struct {
	cluster    *openshiftCluster
	registry   *testRegistryV2
	s1Registry *testRegistryV2
	gpgHome    string
}

func (s *SyncSuite) SetUpSuite(c *check.C) {
	if os.Getenv("SKOPEO_CONTAINER_TESTS") != "1" {
		c.Skip("Not running in a container, refusing to affect user state")
	}

	s.cluster = startOpenshiftCluster(c) // FIXME: Set up TLS for the docker registry port instead of using "--tls-verify=false" all over the place.

	for _, stream := range []string{"unsigned", "personal", "official", "naming", "cosigned", "compression", "schema1", "schema2"} {
		isJSON := fmt.Sprintf(`{
			"kind": "ImageStream",
			"apiVersion": "v1",
			"metadata": {
			    "name": "%s"
			},
			"spec": {}
		}`, stream)
		runCommandWithInput(c, isJSON, "oc", "create", "-f", "-")
	}

	// FIXME: Set up TLS for the docker registry port instead of using "--tls-verify=false" all over the place.
	s.registry = setupRegistryV2At(c, v2DockerRegistryURL, false, false)
	s.s1Registry = setupRegistryV2At(c, v2s1DockerRegistryURL, false, true)

	gpgHome, err := ioutil.TempDir("", "skopeo-gpg")
	c.Assert(err, check.IsNil)
	s.gpgHome = gpgHome
	os.Setenv("GNUPGHOME", s.gpgHome)

	for _, key := range []string{"personal", "official"} {
		batchInput := fmt.Sprintf("Key-Type: RSA\nName-Real: Test key - %s\nName-email: %s@example.com\n%%commit\n",
			key, key)
		runCommandWithInput(c, batchInput, gpgBinary, "--batch", "--gen-key")

		out := combinedOutputOfCommand(c, gpgBinary, "--armor", "--export", fmt.Sprintf("%s@example.com", key))
		err := ioutil.WriteFile(filepath.Join(s.gpgHome, fmt.Sprintf("%s-pubkey.gpg", key)),
			[]byte(out), 0600)
		c.Assert(err, check.IsNil)
	}
}

func (s *SyncSuite) TearDownSuite(c *check.C) {
	if s.gpgHome != "" {
		os.RemoveAll(s.gpgHome)
	}
	if s.registry != nil {
		s.registry.Close()
	}
	if s.s1Registry != nil {
		s.s1Registry.Close()
	}
	if s.cluster != nil {
		s.cluster.tearDown(c)
	}
}

// The most basic (skopeo sync) use:
func (s *SyncSuite) TestSyncSimple(c *check.C) {
	const ourRegistry = "docker://" + v2DockerRegistryURL + "/"

	dir1, err := ioutil.TempDir("", "localdir-1")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir1)
	dir2, err := ioutil.TempDir("", "localdir-2")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(dir2)

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	// "sync": docker: → dir:
	assertSkopeoSucceeds(c, "", "sync", "docker://busybox:latest", "dir:"+dir1)

	// "sync": dir: → docker(v2s2):
	assertSkopeoSucceeds(c, "", "sync", "--dest-tls-verify=false", "dir:"+dir1, ourRegistry+"busybox:unsigned")
	// The result of pushing and pulling is an unmodified image.
	assertSkopeoSucceeds(c, "", "sync", "--src-tls-verify=false", ourRegistry+"busybox:unsigned", "dir:"+dir2)
	out := combinedOutputOfCommand(c, "diff", "-urN", dir1, dir2)
	c.Assert(out, check.Equals, "")

	os.RemoveAll(dir2)
	// "sync": docker(v2s2): → docker(v2s2):
	assertSkopeoSucceeds(c, "", "sync", "--dest-tls-verify=false", "docker://busybox:latest", ourRegistry)
	// The result of pushing and pulling is an unmodified image.
	assertSkopeoSucceeds(c, "", "sync", "--src-tls-verify=false", ourRegistry+"busybox:latest", "dir:"+dir2)
	out = combinedOutputOfCommand(c, "diff", "-urN", dir1, dir2)
	c.Assert(out, check.Equals, "")

	// "sync": dir: → dir is not allowed
	assertSkopeoFails(c, ".*sync from 'dir:' to 'dir:' not implemented.*", "sync", "dir:"+dir1, "dir:"+dir2)
}
