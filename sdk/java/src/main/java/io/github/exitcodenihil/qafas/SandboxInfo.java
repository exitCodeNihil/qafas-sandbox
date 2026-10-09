package io.github.exitcodenihil.qafas;

import java.util.Map;

/** Wire {@code SandboxInfo} (docs/protocol.md). Fields a daemon did not send are null. */
public record SandboxInfo(
        String id, String backend, String template, String state, String workspacePath, String piSession,
        String createdAt, String endpoint, String readyAt, String hostId, String isolation, String lastActivity,
        // v3
        String name, Map<String, String> labels, String stateChangedAt, Integer autoStopSecs, Integer autoArchiveSecs,
        Integer autoDeleteSecs, Integer maxAgeSecs,
        // v4: seconds since last activity (ready|stopped) / since createdAt
        Integer idleSecs, Integer runningSecs,
        // v5: micro|mini|medium|high|custom; enforcement "kernel"|"daemon"; usage = latest boundary sample
        String size, SandboxLimits limits, String enforcement, SandboxUsage usage) {}
