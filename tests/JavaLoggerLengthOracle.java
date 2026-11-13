import gearth.protocol.HPacketFormat;
public class JavaLoggerLengthOracle {
    public static void main(String[] args) {
        for (HPacketFormat format : HPacketFormat.values()) {
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
