import gearth.protocol.HPacketFormat;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class JavaSchedulePacketOracle {
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        for (HPacketFormat format : HPacketFormat.values()) {
            String expression = input.readLine();
            if (expression == null) throw new IllegalArgumentException("missing packet expression");
            System.out.println(HexFormat.of().formatHex(format.createPacket(expression).toBytes()));
        }
    }
}
