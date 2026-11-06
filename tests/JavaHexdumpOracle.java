import gearth.app.services.internal_extensions.uilogger.hexdumper.Hexdump;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class JavaHexdumpOracle {
    public static void main(String[] args) throws Exception {
        String result = Hexdump.hexdump(HexFormat.of().parseHex(args[0]));
        System.out.write(result.getBytes(StandardCharsets.UTF_8));
    }
}
