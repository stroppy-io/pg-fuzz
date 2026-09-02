package build

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Reown gives the build output back to the host user.
//
// WHY THIS IS NOT build.sh's JOB. build.sh ends with
//
//	trap 'chown -R $HOST_UID:$HOST_GID $SRC/postgres $OUT' EXIT
//
// and that is genuinely all it can do, because OSS-Fuzz's `compile` runs the
// coverage source copy AFTER build.sh returns:
//
//	cp -rL --parents $SRC $WORK /usr/include /usr/local/include ... $OUT
//
// By then the trap has fired. Everything that copy lands is root-owned, and it
// is not a rounding error -- 437,176 files and 36G across the coverage builds
// in this checkout, versus a few hundred stray directories from every other
// source combined.
//
// WHY NOT BUILD_UID, which is upstream's own answer. Setting it makes `compile`
// run both the build and the copy as an unprivileged `builder` user. Ours
// cannot: build.sh needs root for useradd, chown and apt-get install. helper.py
// does not thread it through either.
//
// So the build stays privileged and hands the tree back afterwards.
func Reown(ctx context.Context, image, outDir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	uid, gid := os.Getuid(), os.Getgid()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--platform", "linux/amd64",
		"-v", outDir+":/out",
		"-v", self+":/pgfuzz:ro",
		"--entrypoint", "/pgfuzz",
		image, "_own", "/out", fmt.Sprint(uid), fmt.Sprint(gid))
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reown %s: %v\n%s", outDir, err, tail(buf.String(), 20))
	}
	return nil
}
