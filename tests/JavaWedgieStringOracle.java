import gearth.protocol.HPacket;
import gearth.protocol.HPacketFormat;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
public class JavaWedgieStringOracle {
    private static void probe(String name, HPacketFormat format, byte... body) {
        byte[] frame = new byte[body.length + 2];
        frame[0] = 64; frame[1] = 64;
        System.arraycopy(body, 0, frame, 2, body.length);
        HPacket packet = format.createPacket(frame);
        try {
            String value = packet.readString();
            System.out.println(name + "=ok:" + HexFormat.of().formatHex(value.getBytes(StandardCharsets.UTF_8)) + ":" + packet.getReadIndex());
        } catch (RuntimeException error) {
            System.out.println(name + "=error:" + error.getClass().getSimpleName() + ":" + packet.getReadIndex());
        }
    }
    private static void probeAt(String name, HPacket packet, int offset, boolean charset) {
        try {
            String value = charset ? packet.readString(offset, StandardCharsets.ISO_8859_1) : packet.readString(offset);
            System.out.println(name + "=ok:" + HexFormat.of().formatHex(value.getBytes(StandardCharsets.UTF_8)) + ":" + packet.getReadIndex());
        } catch (RuntimeException error) {
            System.out.println(name + "=error:" + error.getClass().getSimpleName() + ":" + packet.getReadIndex());
        }
    }
    public static void main(String[] args) {
        var in = HPacketFormat.WEDGIE_INCOMING;
        var out = HPacketFormat.WEDGIE_OUTGOING;
        probe("in_empty", in, (byte)2);
        probe("in_missing", in);
        probe("in_unterminated", in, (byte)'A', (byte)255);
        probe("in_latin1", in, (byte)255, (byte)2, (byte)'Z');
        probe("out_empty", out, (byte)64, (byte)64);
        probe("out_short_prefix", out, (byte)64);
        probe("out_short_body", out, (byte)64, (byte)66, (byte)'A');
        probe("out_latin1", out, (byte)64, (byte)65, (byte)255);
        probe("out_invalid_prefix", out, (byte)63, (byte)64);
        for (HPacketFormat format : new HPacketFormat[] {in, out}) {
            HPacket packet = format.createPacket(new byte[] {64, 64, 64, 65, 65, 2});
            for (int offset : new int[] {0, 2, 999}) {
                probeAt("at_" + format + "_" + offset, packet, offset, false);
                probeAt("at_charset_" + format + "_" + offset, packet, offset, true);
            }
        }
        HPacket eva = new HPacket(1);
        eva.appendString("hi");
        eva.setReadIndex(7);
        probeAt("at_eva_valid", eva, 6, false);
        probeAt("at_eva_truncated", eva, 999, false);
    }
}
