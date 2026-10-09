package io.github.exitcodenihil.qafas;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Live events of one sandbox. Holds a WebSocket open until {@link #close()}, so always use try-with-resources.
 * Read it either as an {@link Iterable} (blocks for the next event; ends when the server closes; an I/O error
 * surfaces as {@link UncheckedIOException}) or with {@link #poll(Duration)}.
 *
 * <pre>{@code
 * try (EventStream events = sb.events()) {
 *     Event e = events.poll(Duration.ofSeconds(5));
 * }
 * }</pre>
 */
public final class EventStream implements Iterable<Event>, Iterator<Event>, AutoCloseable {
    private final Http.Ws ws;
    private final String sandboxId;
    private Event buffered;
    private boolean done;

    EventStream(Http.Ws ws, String sandboxId) {
        this.ws = ws;
        this.sandboxId = sandboxId;
    }

    /** Next event for this sandbox, or {@code null} if none arrives within {@code timeout} or the stream ended. */
    public Event poll(Duration timeout) throws IOException {
        long deadline = System.nanoTime() + timeout.toNanos();
        long left;
        while ((left = deadline - System.nanoTime()) > 0) {
            String raw = ws.next(Duration.ofNanos(left));
            if (raw == null) return null;
            Event e = parse(raw);
            if (e != null) return e;
        }
        return null;
    }

    /** Frames that are not JSON objects, or belong to another sandbox, are skipped. */
    private Event parse(String raw) {
        try {
            JsonElement j = JsonParser.parseString(raw);
            if (j.isJsonObject() && j.getAsJsonObject().has("sandbox_id")
                    && sandboxId.equals(j.getAsJsonObject().get("sandbox_id").getAsString())) {
                return Http.GSON.fromJson(j, Event.class);
            }
        } catch (JsonParseException | UnsupportedOperationException | IllegalStateException e) {
            // skip non-JSON frames
        }
        return null;
    }

    @Override
    public boolean hasNext() {
        try {
            while (buffered == null && !done) {
                String raw = ws.next();
                if (raw == null) done = true;
                else buffered = parse(raw);
            }
            return buffered != null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public Event next() {
        if (!hasNext()) throw new NoSuchElementException();
        Event e = buffered;
        buffered = null;
        return e;
    }

    @Override
    public Iterator<Event> iterator() {
        return this;
    }

    @Override
    public void close() {
        ws.close();
    }
}
