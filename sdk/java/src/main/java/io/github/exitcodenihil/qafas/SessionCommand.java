package io.github.exitcodenihil.qafas;

/**
 * A command run in a {@link Session}. An async exec answers with {@code commandId} only; the rest (defaults
 * cmd "", state "running", startedAt "") arrives via {@link Session#command}. stdout/stderr come from that GET only.
 */
public record SessionCommand(String commandId, String cmd, String state, String startedAt, Integer exit,
                             String endedAt, String stdout, String stderr) {
    public SessionCommand {
        if (cmd == null) cmd = "";
        if (state == null) state = "running";
        if (startedAt == null) startedAt = "";
    }
}
