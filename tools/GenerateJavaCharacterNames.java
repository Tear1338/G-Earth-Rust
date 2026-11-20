import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;

// Run with JDK 21: java tools/GenerateJavaCharacterNames.java resources/java21-character-names.gz
public class GenerateJavaCharacterNames {
    public static void main(String[] args) throws Exception {
        if (Runtime.version().feature() != 21 || args.length != 1) {
            throw new IllegalArgumentException("JDK 21 and an output path required");
        }
        TreeMap<String, Integer> names = new TreeMap<>();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            String name = Character.getName(cp);
            if (name != null) {
                if (Character.codePointOf(name) != cp || names.put(name, cp) != null) {
                    throw new IllegalStateException("Non-bijective character name: " + name);
                }
            }
        }
        try (var out = new DataOutputStream(new GZIPOutputStream(Files.newOutputStream(Path.of(args[0]))))) {
            out.writeInt(names.size());
            for (var entry : names.entrySet()) {
                byte[] name = entry.getKey().getBytes(StandardCharsets.US_ASCII);
                out.writeShort(name.length);
                out.write(name);
                out.writeInt(entry.getValue());
            }
        }
        System.out.println("Generated " + names.size() + " character names with " + Runtime.version());
    }
}
