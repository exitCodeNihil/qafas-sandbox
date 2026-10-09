package io.github.exitcodenihil.qafas;

import com.google.gson.JsonObject;

/**
 * A named snapshot. {@code state}: building|active|error; {@code kind}: image|vm. {@code warm},
 * {@code memorySnapshot} (default true) and {@code warmReady} are v4.
 */
public record SnapshotInfo(String name, String state, String kind, JsonObject source, String createdAt, Long bytes,
                           String error, String hostId, int warm, Boolean memorySnapshot, int warmReady) {
    public SnapshotInfo {
        if (memorySnapshot == null) memorySnapshot = Boolean.TRUE;
    }
}
