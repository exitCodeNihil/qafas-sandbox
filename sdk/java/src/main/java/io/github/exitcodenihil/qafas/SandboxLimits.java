package io.github.exitcodenihil.qafas;

/**
 * v5 resource ceilings. {@code cpus} moves in 0.25 steps; {@code diskMib} is writable scratch (RAM-backed on
 * vm/remote, so never effectively above {@code memMib}); {@code pids} null = the nearest named size's.
 */
public record SandboxLimits(double cpus, int memMib, int diskMib, Integer pids) {}
