package io.github.exitcodenihil.qafas;

import java.util.List;

public record SessionInfo(String id, String cwd, String createdAt, List<SessionCommand> commands) {}
