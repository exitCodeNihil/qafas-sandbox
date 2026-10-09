package io.github.exitcodenihil.qafas;

/** Result of an exec. {@code timedOut} is only set by the streaming exec. */
public record ExecResult(int exit, String stdout, String stderr, long durationMs, boolean truncated, boolean timedOut) {}
