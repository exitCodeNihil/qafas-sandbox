package io.github.exitcodenihil.qafas.examples;

import io.github.exitcodenihil.qafas.ExecResult;
import io.github.exitcodenihil.qafas.Qafas;
import io.github.exitcodenihil.qafas.Sandbox;

/**
 * Minimal example: acquire a sandbox, run one command, print output, destroy.
 *
 * <pre>SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev  (see sdk/java/README.md for how to run)</pre>
 */
public final class RunCommand {
    public static void main(String[] args) throws Exception {
        // No cwd: the sandbox gets its own /home/agent and nothing is uploaded.
        try (Sandbox sb = Sandbox.create(System.getenv("SANDBOX_URL"), null, "sdk-java-example")) {
            System.out.printf("sandbox %s (%s/%s) workspace=%s%n", sb.id(), sb.backend(), sb.isolation(), sb.workspacePath());
            ExecResult result = sb.execBuffered("uname -a && node -v");
            System.out.print(result.stdout());
            if (!result.stderr().isEmpty()) System.err.print(result.stderr());
            System.out.println("qafas-sandbox " + Qafas.VERSION + ", exit " + result.exit());
        }
    }
}
