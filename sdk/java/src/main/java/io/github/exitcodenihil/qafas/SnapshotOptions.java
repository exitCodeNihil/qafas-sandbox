package io.github.exitcodenihil.qafas;

/**
 * Source and warm-pool knobs for {@link Snapshots#create}: an OCI {@code image} (tag or digest, never
 * {@code latest}), a {@code dockerfile} (text or an {@link Image}), or a live {@code sandboxId}; plus the
 * v4 {@code warm} target and {@code memorySnapshot}. Every setter returns {@code this}.
 */
public final class SnapshotOptions {
    String image;
    String dockerfile;
    String sandboxId;
    Integer warm;
    Boolean memorySnapshot;

    public SnapshotOptions image(String image) {
        this.image = image;
        return this;
    }

    public SnapshotOptions dockerfile(String dockerfile) {
        this.dockerfile = dockerfile;
        return this;
    }

    public SnapshotOptions dockerfile(Image dockerfile) {
        this.dockerfile = dockerfile.toDockerfile();
        return this;
    }

    public SnapshotOptions sandboxId(String sandboxId) {
        this.sandboxId = sandboxId;
        return this;
    }

    public SnapshotOptions warm(int warm) {
        this.warm = warm;
        return this;
    }

    public SnapshotOptions memorySnapshot(boolean memorySnapshot) {
        this.memorySnapshot = memorySnapshot;
        return this;
    }
}
