#!/bin/bash
# PreToolUse hook for Claude Code's Bash tool. Rewrites tool_input.command so
# the command runs inside the Qafas Sandbox instead of on the host, via the
# `sbx run` CLI (sdk/ts/bin/sbx). Registered in settings.json in this directory.
#
# Reads the PreToolUse hook JSON on stdin (docs.claude.com/en/docs/claude-code/hooks),
# emits {hookSpecificOutput:{hookEventName,permissionDecision:"allow",updatedInput}}
# on stdout so Claude Code substitutes the rewritten command before running it.
set -euo pipefail

input=$(cat)
command=$(printf '%s' "$input" | jq -r '.tool_input.command')

url="${SBX_URL:-http://127.0.0.1:7700}"
isolation="${SBX_ISOLATION:-native}"
# design: resolve the sbx CLI from this script's own location, not
# $CLAUDE_PROJECT_DIR — Claude Code sets that to the nearest git root of the
# *session's* cwd, which is the sandboxed workspace (e.g. examples/hello, its
# own nested repo), not necessarily this harness's install directory. Override
# with SBX_CLI if the two ever need to differ.
sbx="${SBX_CLI:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/sdk/ts/bin/sbx}"

# design: printf %q turns the original command into ONE safely-quoted argv
# token, so `sbx run -- <token>` hands the guest the exact original string
# (semicolons, pipes, quotes intact) instead of `sbx run`'s cmdArgs.join(" ")
# silently re-tokenizing a compound command. Escalate to a JSON-array exec
# path only if a command defeats %q in practice (none has in testing).
quoted=$(printf '%q' "$command")
rewritten="$sbx run --url $url --isolation $isolation -- $quoted"

if [[ -n "${SANDBOX_HOOK_LOG:-}" ]]; then
  printf '%s\n' "$rewritten" >> "$SANDBOX_HOOK_LOG"
fi

jq -n --arg cmd "$rewritten" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    updatedInput: {command: $cmd}
  }
}'
