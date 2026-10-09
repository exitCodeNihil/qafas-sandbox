package qafas

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultIgnore is what never leaves the machine: build output and caches (big,
// reproducible), then secrets (small, catastrophic). Same list, same order as
// sdk/python and sdk/ts.
var DefaultIgnore = []string{"node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next", ".cache",
	"*.log", ".env", ".env.*", "!.env.example", "*.pem", "*.key", "id_rsa*", ".aws", ".ssh", ".gnupg",
	".netrc", ".npmrc", ".pypirc", "credentials*", "secrets*"}

type ignoreRule struct {
	re       *regexp.Regexp
	dirOnly  bool
	anchored bool
	negate   bool
}

// compileIgnoreRule: `#` comments, `!` re-includes, a trailing `/` for directories
// only, a `/` anywhere anchors the pattern to the workspace root instead of the basename.
func compileIgnoreRule(line string) *ignoreRule {
	p := strings.TrimSpace(line)
	if p == "" || strings.HasPrefix(p, "#") {
		return nil
	}
	negate := strings.HasPrefix(p, "!")
	if negate {
		p = p[1:]
	}
	dirOnly := strings.HasSuffix(p, "/")
	if dirOnly {
		p = p[:len(p)-1]
	}
	anchored := strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	pat := strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, "[^/]*")
	pat = strings.ReplaceAll(pat, `\?`, "[^/]")
	return &ignoreRule{re: regexp.MustCompile("^" + pat + "$"), dirOnly: dirOnly, anchored: anchored, negate: negate}
}

func compileIgnore(lines []string) []*ignoreRule {
	var rules []*ignoreRule
	for _, l := range lines {
		if r := compileIgnoreRule(l); r != nil {
			rules = append(rules, r)
		}
	}
	return rules
}

// isIgnored: last matching rule wins, so `!.env.example` survives `.env.*`.
func isIgnored(rules []*ignoreRule, rel string, isDir bool) bool {
	name := rel[strings.LastIndex(rel, "/")+1:]
	ignored := false
	for _, r := range rules {
		if r.dirOnly && !isDir {
			continue
		}
		subject := name
		if r.anchored {
			subject = rel
		}
		if r.re.MatchString(subject) {
			ignored = !r.negate
		}
	}
	return ignored
}

// PackWorkspace returns an uncompressed tar of cwd (relative, "/"-separated names;
// symlinks kept as links, never followed) honouring DefaultIgnore, cwd/.sbxignore and
// extraIgnore, in that order, with the same rule engine as sdk/python and sdk/ts.
//
// ponytail: buffers the whole tar in memory; stream into the request body
// (io.Pipe + Sandbox.UploadTar taking an io.Reader) if a very large workspace needs it.
func PackWorkspace(cwd string, extraIgnore ...string) ([]byte, error) {
	lines := append([]string(nil), DefaultIgnore...)
	if b, err := os.ReadFile(filepath.Join(cwd, ".sbxignore")); err == nil {
		lines = append(lines, strings.Split(string(b), "\n")...)
	}
	lines = append(lines, extraIgnore...)
	rules := compileIgnore(lines)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if _, err := os.Stat(cwd); err != nil {
		return nil, err
	}
	if err := packDir(tw, rules, cwd, ""); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func packDir(tw *tar.Writer, rules []*ignoreRule, abs, rel string) error {
	entries, err := os.ReadDir(abs) // sorted by name
	if err != nil {
		if rel == "" {
			return err
		}
		return nil // like os.walk: an unreadable subdirectory is skipped
	}
	var subdirs []string
	for _, e := range entries {
		r := e.Name()
		if rel != "" {
			r = rel + "/" + r
		}
		full := filepath.Join(abs, e.Name())
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			isDir := false
			if st, err := os.Stat(full); err == nil && st.IsDir() {
				isDir = true
			}
			if isIgnored(rules, r, isDir) {
				continue
			}
			target, err := os.Readlink(full)
			if err != nil {
				return err
			}
			if err := addEntry(tw, e, r, target, ""); err != nil {
				return err
			}
		case e.IsDir():
			if !isIgnored(rules, r, true) {
				subdirs = append(subdirs, e.Name())
			}
		case e.Type().IsRegular():
			if isIgnored(rules, r, false) {
				continue
			}
			if err := addEntry(tw, e, r, "", full); err != nil {
				return err
			}
		}
		// sockets, fifos and devices are not workspace content
	}
	for _, d := range subdirs {
		r := d
		if rel != "" {
			r = rel + "/" + d
		}
		if err := packDir(tw, rules, filepath.Join(abs, d), r); err != nil {
			return err
		}
	}
	return nil
}

// addEntry writes a symlink entry (linkname set) or a regular file (full set).
func addEntry(tw *tar.Writer, e fs.DirEntry, name, linkname, full string) error {
	info, err := e.Info()
	if err != nil {
		return err
	}
	h, err := tar.FileInfoHeader(info, linkname)
	if err != nil {
		return err
	}
	h.Name = name
	h.Uname, h.Gname = "", ""
	h.AccessTime, h.ChangeTime = time.Time{}, time.Time{} // keeps the header plain ustar
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if full == "" {
		return nil
	}
	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// UnpackTar extracts a tar (as produced by PackWorkspace or Sandbox.DownloadTar) into
// dest, refusing any member that would land outside it, and symlinks whose target
// escapes it (defence in depth: a compromised or misbehaving host is exactly who this
// guards against). Members before the offending one stay extracted.
func UnpackTar(data []byte, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	realDest, err := filepath.EvalSymlinks(destAbs)
	if err != nil {
		return err
	}
	in := func(root, p string) bool { return p == root || strings.HasPrefix(p, root+string(filepath.Separator)) }
	refuse := func(name string) error {
		return fmt.Errorf("refusing to extract tar member outside destination: %s", name)
	}
	// realOK: the deepest existing ancestor of target, symlinks resolved, is still inside dest.
	realOK := func(target string) bool {
		p := filepath.Dir(target)
		for {
			r, err := filepath.EvalSymlinks(p)
			if err == nil {
				return in(realDest, r)
			}
			if !os.IsNotExist(err) || filepath.Dir(p) == p {
				return false
			}
			p = filepath.Dir(p)
		}
	}

	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if path.IsAbs(h.Name) || filepath.IsAbs(h.Name) {
			return refuse(h.Name)
		}
		target := filepath.Join(destAbs, filepath.FromSlash(h.Name))
		if !in(destAbs, target) || (target != destAbs && !realOK(target)) { // "./" is dest itself
			return refuse(h.Name)
		}
		mode := h.FileInfo().Mode().Perm()
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			os.Remove(target) // never write through an existing symlink
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode|0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			link := h.Linkname
			resolved := filepath.Join(filepath.Dir(target), filepath.FromSlash(link))
			if filepath.IsAbs(link) {
				resolved = filepath.Clean(link)
			}
			if !in(destAbs, resolved) {
				return refuse(h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case tar.TypeLink:
			src := filepath.Join(destAbs, filepath.FromSlash(h.Linkname))
			if path.IsAbs(h.Linkname) || !in(destAbs, src) || !realOK(src) {
				return refuse(h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Link(src, target); err != nil {
				return err
			}
		}
		// other member types (devices, fifos, PAX globals) are ignored
	}
}
