package io.github.exitcodenihil.qafas;

/** Latest boundary usage sample; {@code ts} is an RFC 3339 time. */
public record SandboxUsage(long cpuMillis, long memBytes, long memPeakBytes, long diskBytes, int pids, String ts) {}
