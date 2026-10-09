package qafas

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Live tests run against a real qafas worker and skip when it is unreachable:
//
//	SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev go test -v ./...
//
// SBX_TOKEN must be set for them to run at all (SANDBOX_URL defaults to :7700).
//
// They never pass a local cwd (the worker may be a remote VM that cannot see this
// filesystem) and always destroy what they create.

func liveURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("SANDBOX_URL")
	if url == "" {
		url = "http://127.0.0.1:7700"
	}
	if os.Getenv("SBX_TOKEN") == "" {
		t.Skip("SBX_TOKEN not set (a dev daemon uses SBX_TOKEN=dev)")
	}
	c := http.Client{Timeout: time.Second}
	resp, err := c.Get(url + "/healthz")
	if err != nil {
		t.Skipf("no qafas reachable at %s", url)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Skipf("qafas at %s answers %d", url, resp.StatusCode)
	}
	return url
}

func liveSandbox(t *testing.T, url string) *Sandbox {
	t.Helper()
	sb, err := Acquire(bg, url, "", "sdk-go-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sb.Destroy(context.Background()); err != nil {
			t.Errorf("destroy: %v", err)
		}
	})
	return sb
}

func TestLiveSandbox(t *testing.T) {
	url := liveURL(t)
	sb := liveSandbox(t, url)
	ctx, cancel := context.WithTimeout(bg, 3*time.Minute)
	defer cancel()
	ws := sb.WorkspacePath

	t.Run("acquire", func(t *testing.T) {
		if !strings.HasPrefix(sb.ID, "sbx_") || sb.Backend == "" || sb.Token == "" || ws == "" {
			t.Fatalf("sandbox = %+v", sb)
		}
		t.Logf("%s backend=%s isolation=%s runtime=%s workspace=%s", sb.ID, sb.Backend, sb.Isolation, sb.Runtime(), ws)
	})

	t.Run("exec_buffered", func(t *testing.T) {
		r, err := sb.ExecBuffered(ctx, "echo hello; echo oops >&2; pwd", &ExecOptions{Env: map[string]string{"X": "1"}, ToolCallID: "tc-buf"})
		if err != nil || r.Exit != 0 || !strings.Contains(r.Stdout, "hello") || !strings.Contains(r.Stderr, "oops") || !strings.Contains(r.Stdout, ws) {
			t.Fatalf("result = %+v, %v", r, err)
		}
		if r, err := sb.ExecBuffered(ctx, "exit 3", nil); err != nil || r.Exit != 3 {
			t.Fatalf("exit 3 = %+v, %v", r, err)
		}
	})

	t.Run("exec_stream", func(t *testing.T) {
		var mu sync.Mutex
		var out, errOut strings.Builder
		r, err := sb.Exec(ctx, "echo via-ws; echo err-ws >&2; exit 4", &ExecOptions{OnOutput: func(c []byte, stream string) {
			mu.Lock()
			defer mu.Unlock()
			if stream == "stderr" {
				errOut.Write(c)
			} else {
				out.Write(c)
			}
		}})
		if err != nil || r.Exit != 4 || !strings.Contains(r.Stdout, "via-ws") || !strings.Contains(out.String(), "via-ws") ||
			!strings.Contains(r.Stderr, "err-ws") || !strings.Contains(errOut.String(), "err-ws") {
			t.Fatalf("result = %+v, %v, streamed %q / %q", r, err, out.String(), errOut.String())
		}
		start := time.Now()
		if r, err := sb.Exec(ctx, "exec sleep 4", &ExecOptions{Timeout: time.Second}); err != nil || !r.TimedOut {
			t.Fatalf("timeout = %+v, %v", r, err)
		}
		t.Logf("1s timeout answered after %v", time.Since(start))
	})

	t.Run("fs", func(t *testing.T) {
		dir := ws + "/.sdk_go_fs"
		if err := sb.Mkdir(ctx, dir+"/inner"); err != nil {
			t.Fatal(err)
		}
		if err := sb.WriteString(ctx, dir+"/a b.txt", "roundtrip-ok"); err != nil {
			t.Fatal(err)
		}
		if b, err := sb.ReadFile(ctx, dir+"/a b.txt"); err != nil || string(b) != "roundtrip-ok" {
			t.Fatalf("read = %q, %v", b, err)
		}
		st, err := sb.Stat(ctx, dir+"/a b.txt")
		if err != nil || st.IsDir || st.Size != int64(len("roundtrip-ok")) {
			t.Fatalf("stat = %+v, %v", st, err)
		}
		if st, err := sb.Stat(ctx, dir); err != nil || !st.IsDir {
			t.Fatalf("stat dir = %+v, %v", st, err)
		}
		names, err := sb.ListDir(ctx, dir)
		if err != nil || strings.Join(names, ",") != "a b.txt,inner" {
			t.Fatalf("list = %v, %v", names, err)
		}
		for _, err := range []error{
			func() error { _, err := sb.ReadFile(ctx, dir+"/missing"); return err }(),
			func() error { _, err := sb.Stat(ctx, dir+"/missing"); return err }(),
			func() error { _, err := sb.ListDir(ctx, dir+"/missing"); return err }(),
		} {
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("want ErrNotFound, got %v", err)
			}
		}
		if _, err := sb.ExecBuffered(ctx, "rm -rf '"+dir+"'", nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("upload_download", func(t *testing.T) {
		local, back := t.TempDir(), t.TempDir()
		write(t, local, "hello.txt", "hello sandbox")
		write(t, local, "sub/nested.txt", "nested")
		write(t, local, ".env", "SECRET=not-uploaded")
		remoteFile, remoteDir := ws+"/.sdk_go_up.txt", ws+"/.sdk_go_updir"
		defer sb.ExecBuffered(ctx, "rm -rf '"+remoteFile+"' '"+remoteDir+"'", nil)

		if err := sb.Upload(ctx, filepath.Join(local, "hello.txt"), remoteFile, false); err != nil {
			t.Fatal(err)
		}
		if b, err := sb.ReadFile(ctx, remoteFile); err != nil || string(b) != "hello sandbox" {
			t.Fatalf("read = %q, %v", b, err)
		}
		if err := sb.Mkdir(ctx, remoteDir); err != nil {
			t.Fatal(err)
		}
		if err := sb.Upload(ctx, local, remoteDir, false); err != nil {
			t.Fatal(err)
		}
		names, err := sb.ListDir(ctx, remoteDir)
		if err != nil || strings.Join(names, ",") != "hello.txt,sub" {
			t.Fatalf("list = %v, %v (.env must not travel)", names, err)
		}
		if err := sb.Download(ctx, remoteFile, filepath.Join(back, "x", "hello.txt"), false); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(back, "x", "hello.txt")); string(b) != "hello sandbox" {
			t.Fatalf("downloaded file = %q", b)
		}
		if err := sb.Download(ctx, remoteDir, filepath.Join(back, "updir"), false); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(back, "updir", "sub", "nested.txt")); string(b) != "nested" {
			t.Fatalf("downloaded nested = %q", b)
		}
		// download_tar + unpack_tar by hand
		tarBytes, err := sb.DownloadTar(ctx, remoteDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := UnpackTar(tarBytes, filepath.Join(back, "manual")); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(back, "manual", "hello.txt")); string(b) != "hello sandbox" {
			t.Fatalf("manual unpack = %q", b)
		}
		if err := sb.Upload(ctx, local, "/etc/qafas-sdk-go", false); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
			t.Fatalf("guard err = %v", err)
		}
	})

	t.Run("processes_info_preview", func(t *testing.T) {
		procs, err := sb.Processes(ctx)
		if err != nil || procs == nil {
			t.Fatalf("processes = %v, %v", procs, err)
		}
		info, err := sb.Info(ctx)
		if err != nil || info.ID != sb.ID || info.State == "" {
			t.Fatalf("info = %+v, %v", info, err)
		}
		ttl := 60
		p, err := sb.Preview(ctx, 8080, &ttl)
		if err != nil || p.Port != 8080 || p.URL == "" || p.Token == "" {
			t.Fatalf("preview = %+v, %v", p, err)
		}
	})

	t.Run("sessions", func(t *testing.T) {
		sess, err := sb.CreateSession(ctx, &SessionOptions{Cwd: ws})
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Delete(context.Background())
		c, err := sess.Exec(ctx, "export SDK_GO=persisted; echo sync-ok", nil)
		if err != nil || c.Exit == nil || *c.Exit != 0 || c.Stdout == nil || !strings.Contains(*c.Stdout, "sync-ok") {
			t.Fatalf("sync exec = %+v, %v", c, err)
		}
		ac, err := sess.Exec(ctx, "echo $SDK_GO; sleep 1; echo async-done", &SessionExecOptions{Async: true})
		if err != nil || ac.CommandID == "" {
			t.Fatalf("async exec = %+v, %v", ac, err)
		}
		var streamed strings.Builder
		final, err := sess.Logs(ctx, ac.CommandID, func(chunk []byte, stream string) { streamed.Write(chunk) })
		if err != nil || final.State != "done" || final.Stdout == nil || !strings.Contains(*final.Stdout, "persisted") || !strings.Contains(*final.Stdout, "async-done") {
			t.Fatalf("logs final = %+v, %v", final, err)
		}
		if !strings.Contains(streamed.String(), "async-done") {
			t.Fatalf("streamed = %q", streamed.String())
		}
		if got, err := sess.Command(ctx, ac.CommandID); err != nil || got.State != "done" {
			t.Fatalf("command = %+v, %v", got, err)
		}
		if err := sess.Delete(ctx); err != nil {
			t.Fatal(err)
		}
		if err := sess.Delete(ctx); err != nil { // already gone: 404 is success
			t.Fatal(err)
		}
	})

	t.Run("events", func(t *testing.T) {
		ectx, ecancel := context.WithTimeout(ctx, 20*time.Second)
		defer ecancel()
		got := make(chan Event, 1)
		done := make(chan error, 1)
		go func() {
			done <- sb.Events(ectx, func(e Event) error {
				select {
				case got <- e:
				default:
				}
				return nil
			})
		}()
		// keep running commands until a frame for this sandbox shows up
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		var ev Event
	wait:
		for {
			select {
			case ev = <-got:
				break wait
			case err := <-done:
				t.Fatalf("events ended early: %v", err)
			case <-ectx.Done():
				t.Fatal("no event for this sandbox within 20s")
			case <-tick.C:
				sb.ExecBuffered(ctx, "true", &ExecOptions{ToolCallID: "tc-events"})
			}
		}
		if ev.SandboxID != sb.ID || ev.Type == "" {
			t.Fatalf("event = %+v", ev)
		}
		ecancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("events end = %v", err)
		}
	})

	t.Run("lifecycle_vm_tier", func(t *testing.T) {
		if sb.Isolation == "remote" {
			t.Skip("remote tier: stop/archive are real here")
		}
		// stop/archive are remote-tier only; assert the error type, not success.
		for name, fn := range map[string]func(context.Context) error{"stop": sb.Stop, "archive": sb.Archive} {
			var he *Error
			if err := fn(ctx); err != nil && !errors.As(err, &he) {
				t.Errorf("%s: want *Error, got %T %v", name, err, err)
			} else if err != nil {
				t.Logf("%s -> %v", name, err)
			}
		}
	})

	t.Run("cdp_url", func(t *testing.T) {
		if !strings.HasPrefix(sb.CDPURL(), "ws") || !strings.HasSuffix(sb.CDPURL(), "/browser/cdp") {
			t.Fatalf("cdp = %s", sb.CDPURL())
		}
	})
}

func TestLiveSnapshots(t *testing.T) {
	url := liveURL(t)
	snaps := NewSnapshots(url, "")
	list, err := snaps.List(bg)
	if err != nil {
		var he *Error
		if errors.As(err, &he) && (he.Status == 401 || he.Status == 403) {
			t.Skipf("snapshots need the admin token: %v", err)
		}
		t.Fatal(err)
	}
	base, err := snaps.Get(bg, "base")
	if err != nil || base.Name != "base" {
		t.Fatalf("get base = %+v, %v (list has %d)", base, err, len(list))
	}
	if err := snaps.Delete(bg, "sdk-go-no-such-snapshot"); err != nil {
		t.Fatalf("deleting a missing snapshot must be a no-op: %v", err)
	}
}

func TestLiveDestroyTwiceIsNoop(t *testing.T) {
	url := liveURL(t)
	sb, err := Acquire(bg, url, "", "sdk-go-destroy", &AcquireOptions{Name: "sdk-go-destroy-twice", Labels: map[string]string{"sdk": "go"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sb.Destroy(bg); err != nil {
			t.Fatalf("destroy #%d: %v", i+1, err)
		}
	}
	if err := sb.Delete(bg); err != nil {
		t.Fatal(err)
	}
}
