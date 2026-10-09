package io.github.exitcodenihil.qafas;

import java.util.List;
import java.util.Map;

/**
 * Optional knobs of {@link Qafas#acquire} / {@link Sandbox#create}; build with {@link #builder()}.
 *
 * <p>{@code runtime} ({@code auto|process|docker|firecracker}) maps to {@code isolation}
 * ({@code native|vm|remote}) and wins when both are given; with neither the request carries no
 * {@code isolation} and the daemon picks. {@code snapshot} aliases {@code template}. {@code size}
 * ({@code micro|mini|medium|high}) and {@code limits} are mutually exclusive (both is a 400). Only the
 * caller of acquire picks size/limits: never expose them as a tool parameter a model can set.
 * {@code token} overrides the bearer; otherwise a worker uses {@code $SBX_TOKEN} and the control plane
 * {@code apiKey}, {@code $SBX_API_KEY}, {@code $SBX_ADMIN_TOKEN}.
 */
public final class AcquireOptions {
    String apiKey;
    String isolation;
    String runtime;
    String trust = "trusted";
    List<String> tools = List.of();
    List<String> egressAllow = List.of();
    Integer ttlSecs;
    String token;
    String template = "base";
    String snapshot;
    String name;
    Map<String, String> labels;
    Map<String, String> env;
    Integer autoStopSecs;
    Integer autoArchiveSecs;
    Integer autoDeleteSecs;
    Integer maxAgeSecs;
    String size;
    SandboxLimits limits;
    boolean uploadWorkspace = true;

    private AcquireOptions() {}

    static AcquireOptions defaults() {
        return new AcquireOptions();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final AcquireOptions o = new AcquireOptions();

        public Builder apiKey(String v) { o.apiKey = v; return this; }
        public Builder isolation(String v) { o.isolation = v; return this; }
        public Builder runtime(String v) { o.runtime = v; return this; }
        public Builder trust(String v) { o.trust = v; return this; }
        public Builder tools(List<String> v) { o.tools = v; return this; }
        public Builder egressAllow(List<String> v) { o.egressAllow = v; return this; }
        public Builder ttlSecs(int v) { o.ttlSecs = v; return this; }
        public Builder token(String v) { o.token = v; return this; }
        public Builder template(String v) { o.template = v; return this; }
        public Builder snapshot(String v) { o.snapshot = v; return this; }
        public Builder name(String v) { o.name = v; return this; }
        public Builder labels(Map<String, String> v) { o.labels = v; return this; }
        public Builder env(Map<String, String> v) { o.env = v; return this; }
        public Builder autoStopSecs(int v) { o.autoStopSecs = v; return this; }
        public Builder autoArchiveSecs(int v) { o.autoArchiveSecs = v; return this; }
        public Builder autoDeleteSecs(int v) { o.autoDeleteSecs = v; return this; }
        public Builder maxAgeSecs(int v) { o.maxAgeSecs = v; return this; }
        public Builder size(String v) { o.size = v; return this; }
        public Builder limits(SandboxLimits v) { o.limits = v; return this; }
        /** On the remote tier a given cwd is tarred and uploaded unless this is false (default true). */
        public Builder uploadWorkspace(boolean v) { o.uploadWorkspace = v; return this; }

        /** Single use: the builder hands out its own instance. */
        public AcquireOptions build() { return o; }
    }
}
