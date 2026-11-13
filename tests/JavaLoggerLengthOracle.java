import gearth.protocol.HPacketFormat;
public class JavaLoggerLengthOracle {
    public static void main(String[] args) {
        for (int value = 0; value < 256; value++) {
            String text = gearth.services.packet_representation.PacketStringUtils.toString(new byte[] {(byte)value});
            System.out.println("BYTE:" + value + "=" + java.util.Base64.getEncoder().encodeToString(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
        for (HPacketFormat format : HPacketFormat.values()) {
            byte[] full = new byte[256 + (format == HPacketFormat.EVA_WIRE ? 6 : 2)];
            if (format == HPacketFormat.EVA_WIRE) { full[2] = 1; full[3] = 2; }
            else { full[0] = 64; full[1] = 64; }
            for (int value = 0; value < 256; value++) full[full.length - 256 + value] = (byte)value;
            String display = format.createPacket(full).toString();
            System.out.println("DISPLAY:" + format + "=" + java.util.Base64.getEncoder().encodeToString(display.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            for (int length : new int[] {1000, 1001, 2000, 2001, 4000, 4001}) {
                byte[] bytes = new byte[length + (format == HPacketFormat.EVA_WIRE ? 4 : 0)];
                if (format == HPacketFormat.EVA_WIRE) {
                    bytes[0] = (byte)(length >>> 24); bytes[1] = (byte)(length >>> 16);
                    bytes[2] = (byte)(length >>> 8); bytes[3] = (byte)length;
                } else { bytes[0] = 64; bytes[1] = 64; }
                int observed = format.createPacket(bytes).length();
                if (observed != length) throw new AssertionError(format + ": " + observed + " != " + length);
                System.out.println(format + ":" + length + "=" + observed);
            }
        }
    }
}
