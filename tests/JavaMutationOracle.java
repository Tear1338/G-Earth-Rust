import gearth.protocol.HPacket;
import java.util.HexFormat;

public class JavaMutationOracle {
    static void emit(String name, HPacket packet) {
        System.out.println(name + "=" + HexFormat.of().formatHex(packet.toBytes()) + "," + packet.getReadIndex());
    }
    public static void main(String[] args) {
        HPacket fixed = new HPacket(1);
        fixed.appendInt(123).appendBoolean(false).appendShort((short) 7).appendLong(8).appendFloat(1.5f).appendDouble(2.5);
        fixed.setReadIndex(10);
        fixed.replaceInt(6, -77).replaceBoolean(10, true).replaceUShort(11, 65000).replaceLong(13, -9999999999L).replaceFloat(21, -3.25f).replaceDouble(25, 0.125);
        emit("fixed", fixed);
        HPacket growth = new HPacket(2);
        growth.appendString("cat").appendInt(42).appendString("end");
        growth.setReadIndex(7);
        growth.replaceString(6, "caterpillar");
        emit("growth", growth);
        HPacket shrink = new HPacket(2);
        shrink.appendString("elephant").appendInt(42).appendString("end");
        shrink.setReadIndex(7);
        shrink.replaceString(6, "x");
        emit("shrink", shrink);
        HPacket strings = new HPacket(3);
        strings.appendString("cat").appendInt(123).appendString("cat").appendString("dog").appendString("cat");
        strings.setReadIndex(8);
        strings.replaceXStrings("cat", "longer", 2);
        emit("strings", strings);
        HPacket integers = new HPacket(4);
        integers.appendByte((byte) 42).appendInt(123456).appendInt(123456).appendByte((byte) 10);
        integers.setReadIndex(7);
        integers.replaceAllIntegers(123456, -7);
        emit("integers", integers);
        HPacket emptyGrowth = new HPacket(5);
        emptyGrowth.appendString("").appendString("a");
        emptyGrowth.setReadIndex(7);
        emptyGrowth.replaceString(6, "x");
        emit("empty_growth_original", emptyGrowth);
        String[] oldValues = {"a", "abc", "é"};
        String[] values = {"", "a", "abc", "é"};
        int[] limits = {0, 1, 2, -1};
        for (int oldIndex = 0; oldIndex < oldValues.length; oldIndex++) {
            for (int newIndex = 0; newIndex < values.length; newIndex++) {
                for (int limitIndex = 0; limitIndex < limits.length; limitIndex++) {
                    HPacket sample = new HPacket(5);
                    sample.appendString("").appendString("a").appendInt(1).appendString("abc").appendString("é").appendString("a").appendString("");
                    sample.setReadIndex(7);
                    sample.replaceXStrings(oldValues[oldIndex], values[newIndex], limits[limitIndex]);
                    emit("strings_" + oldIndex + "_" + newIndex + "_" + limitIndex, sample);
                }
            }
        }
    }
}
