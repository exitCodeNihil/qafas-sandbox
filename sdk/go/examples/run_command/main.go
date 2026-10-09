// Minimal example: acquire a sandbox, run one command, print output, destroy.
//
//	SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev go run ./examples/run_command
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	qafas "github.com/exitCodeNihil/qafas-sandbox/sdk/go"
)

func main() {
	ctx := context.Background()
	cwd, _ := os.Getwd()
	sb, err := qafas.Acquire(ctx, os.Getenv("SANDBOX_URL"), cwd, "sdk-go-example", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer sb.Destroy(ctx)

	fmt.Printf("sandbox %s (%s/%s) workspace=%s\n", sb.ID, sb.Backend, sb.Isolation, sb.WorkspacePath)
	res, err := sb.ExecBuffered(ctx, "uname -a && node -v", nil)
	if err != nil {
		sb.Destroy(ctx)
		log.Fatal(err)
	}
	fmt.Print(res.Stdout)
	fmt.Fprint(os.Stderr, res.Stderr)
	if res.Exit != 0 {
		sb.Destroy(ctx) // os.Exit skips the defer
		os.Exit(res.Exit)
	}
}
