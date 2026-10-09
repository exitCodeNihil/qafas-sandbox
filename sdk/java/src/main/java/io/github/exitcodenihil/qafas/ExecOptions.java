package io.github.exitcodenihil.qafas;

import java.time.Duration;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * Optional knobs of {@link Sandbox#exec} / {@link Sandbox#execBuffered}; every setter returns {@code this}.
 * {@code cwd} defaults to the sandbox workspace path; {@code env} is merged into the command's environment;
 * {@code onOutput} receives {@code (chunk, "stdout"|"stderr")} on the calling thread and is used by the
 * streaming {@code exec} only; {@code toolCallId} is sent as {@code x-tool-call-id}.
 */
public final class ExecOptions {
    String cwd;
    Map<String, String> env;
    Duration timeout;
    BiConsumer<byte[], String> onOutput;
    String toolCallId = "";

    public ExecOptions cwd(String cwd) {
        this.cwd = cwd;
        return this;
    }

    public ExecOptions env(Map<String, String> env) {
        this.env = env;
        return this;
    }

    public ExecOptions timeout(Duration timeout) {
        this.timeout = timeout;
        return this;
    }

    public ExecOptions onOutput(BiConsumer<byte[], String> onOutput) {
        this.onOutput = onOutput;
        return this;
    }

    public ExecOptions toolCallId(String toolCallId) {
        this.toolCallId = toolCallId == null ? "" : toolCallId;
        return this;
    }
}
