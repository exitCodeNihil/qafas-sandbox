package qafas

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// Image is a declarative Dockerfile builder for Snapshots.Create (docs/protocol.md
// "Snapshots"). Output is byte-identical to sdk/python's Image. Plain string
// concatenation, not a Dockerfile AST: a snapshot build is a one-shot server-side step.
type Image struct{ lines []string }

// NewImage starts a Dockerfile `FROM base`.
func NewImage(base string) *Image { return &Image{lines: []string{"FROM " + base}} }

// shQuote single-quotes s for a POSIX shell, escaping embedded quotes.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shQuoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = shQuote(s)
	}
	return strings.Join(q, " ")
}

func (i *Image) add(format string, a ...any) *Image {
	i.lines = append(i.lines, fmt.Sprintf(format, a...))
	return i
}

// Run appends `RUN cmd`.
func (i *Image) Run(cmd string) *Image { return i.add("RUN %s", cmd) }

// Workdir appends `WORKDIR dir`.
func (i *Image) Workdir(dir string) *Image { return i.add("WORKDIR %s", dir) }

// Env appends one `ENV K="v"` line per entry. Go maps have no insertion order, so
// entries of one call are sorted by key; call Env repeatedly to control the order.
func (i *Image) Env(vars map[string]string) *Image {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		i.add("ENV %s=\"%s\"", k, vars[k])
	}
	return i
}

// PipInstall appends `RUN pip install --no-cache-dir ...` (nothing when pkgs is empty).
func (i *Image) PipInstall(pkgs ...string) *Image {
	if len(pkgs) == 0 {
		return i
	}
	return i.add("RUN pip install --no-cache-dir %s", shQuoteAll(pkgs))
}

// NpmInstall appends `RUN npm install -g ...` (nothing when pkgs is empty).
func (i *Image) NpmInstall(pkgs ...string) *Image {
	if len(pkgs) == 0 {
		return i
	}
	return i.add("RUN npm install -g %s", shQuoteAll(pkgs))
}

// CopyText writes content to destPath in the image. A Dockerfile COPY needs a build
// context file that does not exist here, so the content travels as base64 and is
// decoded in a RUN step.
func (i *Image) CopyText(destPath, content string) *Image {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	return i.add(`RUN mkdir -p "$(dirname %s)" && echo %s | base64 -d > %s`, shQuote(destPath), shQuote(b64), shQuote(destPath))
}

// ToDockerfile renders the Dockerfile: lines joined with "\n" plus a trailing "\n".
func (i *Image) ToDockerfile() string { return strings.Join(i.lines, "\n") + "\n" }

// String is ToDockerfile.
func (i *Image) String() string { return i.ToDockerfile() }
