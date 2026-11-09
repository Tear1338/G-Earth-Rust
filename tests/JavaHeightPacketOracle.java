import gearth.extensions.parsers.HEntity;
import gearth.extensions.parsers.HFloorItem;
import gearth.protocol.HPacket;
import java.util.HexFormat;
public class JavaHeightPacketOracle {
    public static void main(String[] args) {
        long[] samples = {1, 2, Long.MIN_VALUE | 1, 0x0010000000000000L, 0x7fefffffffffffffL, Double.doubleToRawLongBits(1e23), Double.doubleToRawLongBits(-0.0)};
        for (long bits : samples) {
            String height = Double.toString(Double.longBitsToDouble(bits));
            HPacket entityInput = new HPacket(1);
            entityInput.appendInt(17).appendString("Bot").appendString("hello").appendString("figure").appendInt(23).appendInt(3).appendInt(4).appendString(height).appendInt(5).appendInt(3);
            HPacket entityOutput = new HPacket(42);
            new HEntity(entityInput).appendToPacket(entityOutput);
            HPacket furnitureInput = new HPacket(1);
            furnitureInput.appendInt(17).appendInt(4).appendInt(3).appendInt(4).appendInt(1).appendString(height).appendString("1").appendInt(0).appendInt(0).appendString("0").appendInt(0).appendInt(0).appendInt(99);
            HPacket furnitureOutput = new HPacket(42);
            new HFloorItem(furnitureInput).appendToPacket(furnitureOutput);
            System.out.printf("%016x=%s;%s;%s%n", bits, height, HexFormat.of().formatHex(entityOutput.toBytes()), HexFormat.of().formatHex(furnitureOutput.toBytes()));
        }
    }
}
