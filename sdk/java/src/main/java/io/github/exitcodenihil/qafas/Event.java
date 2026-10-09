package io.github.exitcodenihil.qafas;

import com.google.gson.JsonElement;

/** One frame of the {@code /events/ws} firehose; {@code data} is the type-specific payload. */
public record Event(String id, String ts, String hostId, String sandboxId, String piSession, String toolCallId,
                    String type, JsonElement data) {}
