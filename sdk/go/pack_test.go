package qafas

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func members(t *testing.T, tarBytes []byte) map[string]*tar.Header {
	t.Helper()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		h, err := tr.Next()
		if err != nil {
			return out
		}
		out[h.Name] = h
	}
}

func names(t *testing.T, tarBytes []byte) []string {
	var n []string
	for k := range members(t, tarBytes) {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func pack(t *testing.T, root string) []byte {
	t.Helper()
	b, err := PackWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDefaultIgnoreExcludesSecretsAndBuildOutput(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/main.py", "x")
	write(t, root, ".git/config", "x")
	write(t, root, ".env", "OPENAI_API_KEY=sk-live")
	write(t, root, ".env.example", "OPENAI_API_KEY=")
	write(t, root, "node_modules/left-pad/index.js", "x")
	write(t, root, "dist/bundle.js", "x")
	write(t, root, "deploy/server.key", "x")
	write(t, root, ".ssh/id_rsa", "x")
	write(t, root, "credentials.json", "x")
	write(t, root, "debug.log", "x")

	got := names(t, pack(t, root))
	want := []string{".env.example", ".git/config", "src/main.py"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
}

func TestSbxignoreAnchoredDirOnlyAndNegatedRules(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/main.py", "x")
	write(t, root, "secrets/db.json", "x") // dir-only rule "secrets/" excludes the whole tree
	write(t, root, "notes/keep.txt", "x")  // negated "!keep.txt" survives a broader exclude
	write(t, root, "notes/draft.txt", "x")
	write(t, root, "vendor/notes/draft.txt", "x") // anchored "notes/draft.txt" must NOT match this nested copy
	write(t, root, ".sbxignore", "secrets/\nnotes/draft.txt\n!keep.txt\n")

	got := names(t, pack(t, root))
	want := []string{".sbxignore", "notes/keep.txt", "src/main.py", "vendor/notes/draft.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
}

func TestExtraIgnoreAndRuleEngineDetails(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.txt", "x")
	write(t, root, "b.tmp", "x")
	write(t, root, "sub/c.tmp", "x")
	write(t, root, "sub/d.txt", "x")
	write(t, root, ".sbxignore", "# a comment\n\n  \n*.tmp\n")
	b, err := PackWorkspace(root, "a.t?t")
	if err != nil {
		t.Fatal(err)
	}
	got := names(t, b)
	want := []string{".sbxignore", "sub/d.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
	if len(DefaultIgnore) != 24 || DefaultIgnore[0] != "node_modules" || DefaultIgnore[23] != "secrets*" {
		t.Fatalf("DefaultIgnore drifted from python/ts: %d entries", len(DefaultIgnore))
	}
}

func TestSymlinksTravelAsLinksAndAreNotFollowed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "real/f.txt", "x")
	for name, target := range map[string]string{"linkdir": "real", "linkfile": "real/f.txt", "outside": "/etc/passwd"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	m := members(t, pack(t, root))
	for name, target := range map[string]string{"linkdir": "real", "linkfile": "real/f.txt", "outside": "/etc/passwd"} {
		h := m[name]
		if h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != target {
			t.Fatalf("%s = %+v, want symlink -> %s", name, h, target)
		}
	}
	if _, ok := m["linkdir/f.txt"]; ok {
		t.Fatal("a symlinked directory must not be descended into")
	}
	if m["real/f.txt"] == nil {
		t.Fatal("real/f.txt missing")
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "out")
	write(t, src, "a/b.txt", "hello")
	if err := os.Symlink("b.txt", filepath.Join(src, "a", "ln")); err != nil {
		t.Fatal(err)
	}
	if err := UnpackTar(pack(t, src), dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a", "b.txt")); string(b) != "hello" {
		t.Fatalf("content = %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "a", "ln")); l != "b.txt" {
		t.Fatalf("link = %q", l)
	}
}

func tarOf(t *testing.T, hs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hs {
		if h.Typeflag == tar.TypeReg {
			h.Size = 1
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("x"))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func TestUnpackRefusesEscapes(t *testing.T) {
	reg := func(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644} }
	sym := func(name, to string) *tar.Header {
		return &tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: to, Mode: 0o777}
	}
	cases := map[string][]*tar.Header{
		"../x":        {reg("../x")},
		"/abs/x":      {reg("/tmp/qafas-unpack-abs")},
		"a/../../x":   {reg("a/../../x")},
		"sym-up":      {sym("l", "../..")},
		"sym-abs":     {sym("l", "/etc")},
		"sym-then-fs": {sym("l", "."), sym("l2", "l/.."), reg("l2/x")},
	}
	for name, hs := range cases {
		dest := filepath.Join(t.TempDir(), "d")
		err := UnpackTar(tarOf(t, hs...), dest)
		if err == nil || !strings.Contains(err.Error(), "refusing to extract tar member outside destination") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := os.Stat("/tmp/qafas-unpack-abs"); err == nil {
		t.Fatal("absolute member was written")
	}
	// nothing after the offending member is extracted
	dest := filepath.Join(t.TempDir(), "d")
	_ = UnpackTar(tarOf(t, reg("ok.txt"), reg("../bad"), reg("late.txt")), dest)
	if _, err := os.Stat(filepath.Join(dest, "ok.txt")); err != nil {
		t.Fatal("member before the offender should be extracted")
	}
	if _, err := os.Stat(filepath.Join(dest, "late.txt")); err == nil {
		t.Fatal("member after the offender must not be extracted")
	}
}
