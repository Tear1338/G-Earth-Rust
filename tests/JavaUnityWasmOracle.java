import java.nio.file.Files;
import java.nio.file.Path;
import gearth.app.services.unity_tools.WasmCodePatcher;

/** Runs the original pinned patchers against the actual released G-Wasm library. */
public final class JavaUnityWasmOracle {
    public static void main(String[] args) throws Exception {
        byte[] input=Files.readAllBytes(Path.of(args[0]));
        Files.write(Path.of(args[1]),new WasmCodePatcher(input).patch(false));
        System.out.println("Original beta-29 Unity patchers produced an executable oracle fixture");
    }
}
