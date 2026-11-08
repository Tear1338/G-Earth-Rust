import gearth.protocol.HPacket;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;

public class JavaMutationOracle {
    static void emit(String name, HPacket packet) {
        System.out.println(name + "=" + HexFormat.of().formatHex(packet.toBytes()) + "," + packet.getReadIndex());
    }
    public static void main(String[] args) {
        HPacket malformedUtf = new HPacket(16);
        malformedUtf.appendUShort(3).appendBytes(new byte[]{(byte)0xe2, (byte)0x82, 0x41});
        malformedUtf.appendInt(2).appendBytes(new byte[]{(byte)0xff, 0x61});
        malformedUtf.setReadIndex(7);
        System.out.println("utf8_malformed=" + HexFormat.of().formatHex(malformedUtf.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)) + "," + HexFormat.of().formatHex(malformedUtf.readLongString(11, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)) + "," + malformedUtf.getReadIndex());
        HPacket utfAt = new HPacket(15);
        utfAt.appendString("Café 🐱", StandardCharsets.UTF_8).appendLongString("éclair", StandardCharsets.UTF_8);
        utfAt.setReadIndex(7);
        System.out.println("utf8_offsets=" + HexFormat.of().formatHex(utfAt.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)) + "," + HexFormat.of().formatHex(utfAt.readLongString(18, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)) + "," + utfAt.getReadIndex());
        HPacket signedBytes = new HPacket(14);
        signedBytes.appendByte(Byte.MIN_VALUE).appendByte((byte) -1).appendByte((byte) 0).appendByte(Byte.MAX_VALUE);
        signedBytes.setReadIndex(7);
        signedBytes.replaceByte(7, (byte) -42);
        System.out.println("signed_bytes=" + signedBytes.readByte(6) + "," + signedBytes.readByte(7) + "," + signedBytes.readByte(8) + "," + signedBytes.readByte(9) + "," + signedBytes.getReadIndex());
        emit("signed_byte_packet", signedBytes);
        HPacket shorts = new HPacket(13);
        shorts.appendShort(Short.MIN_VALUE).appendShort((short) -1).appendShort((short) 0).appendShort(Short.MAX_VALUE);
        shorts.setReadIndex(8);
        shorts.replaceShort(8, (short) -1234);
        System.out.println("signed_shorts=" + shorts.readShort(6) + "," + shorts.readShort(8) + "," + shorts.readShort(10) + "," + shorts.readShort(12) + "," + shorts.getReadIndex());
        emit("signed_short_bytes", shorts);
        HPacket fixed = new HPacket(1);
        fixed.appendInt(123).appendBoolean(false).appendShort((short) 7).appendLong(8).appendFloat(1.5f).appendDouble(2.5);
        fixed.setReadIndex(10);
        fixed.replaceInt(6, -77).replaceBoolean(10, true).replaceUShort(11, 65000).replaceLong(13, -9999999999L).replaceFloat(21, -3.25f).replaceDouble(25, 0.125);
        emit("fixed", fixed);
        HPacket rawBytes = new HPacket(10);
        rawBytes.appendBytes(new byte[]{0, 1, 2, 3, 4, 5});
        rawBytes.setReadIndex(8);
        rawBytes.replaceBytes(7, new byte[]{(byte) 0xff, (byte) 0x80, 42});
        emit("fixed_bytes", rawBytes);
        HPacket randomReads = new HPacket(77);
        randomReads.appendByte((byte) 0xff).appendUShort(65000).appendInt(-123456)
            .appendLong(-9000000000L).appendFloat(-3.25f).appendDouble(0.125)
            .appendString("cafe").appendLongString("long");
        randomReads.setReadIndex(8);
        System.out.println("random_reads=" + Byte.toUnsignedInt(randomReads.readByte(6)) + ","
            + randomReads.readBoolean(6) + "," + randomReads.readUshort(7) + ","
            + randomReads.readInteger(9) + "," + randomReads.readLong(13) + ","
            + randomReads.readFloat(21) + "," + randomReads.readDouble(25) + ","
            + randomReads.readString(33) + "," + randomReads.readLongString(39) + ","
            + randomReads.readInteger(0) + "," + randomReads.getReadIndex());
        HPacket skipped = new HPacket(11);
        skipped.appendInt(42).appendString("hello").appendByte((byte) 4).appendBoolean(true)
            .appendShort((short) 1234).appendLong(123456789L).appendDouble(2.5);
        skipped.skip("i s?bBul d");
        System.out.println("skip_full=" + skipped.getReadIndex() + "," + skipped.isEOF());
        HPacket partialSkip = new HPacket(12);
        partialSkip.appendInt(42);
        try {
            partialSkip.skip("ib");
        } catch (IndexOutOfBoundsException expected) {
            System.out.println("skip_partial=" + partialSkip.getReadIndex() + "," + partialSkip.isEOF());
        }
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
        for (int limit : new int[]{1, 2, -1}) {
            HPacket substring = new HPacket(9);
            substring.appendString("cat cat").appendString("catdog");
            substring.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                substring.replaceXSubstrings("cat", "hello", limit);
            } finally {
                System.setOut(original);
            }
            emit("substring_" + limit, substring);
        }
        HPacket emptyGrowth = new HPacket(5);
        emptyGrowth.appendString("").appendString("a");
        emptyGrowth.setReadIndex(7);
        emptyGrowth.replaceString(6, "x");
        emit("empty_growth_original", emptyGrowth);
        HPacket utf8 = new HPacket(6);
        utf8.appendString("café 🐱", StandardCharsets.UTF_8).appendLongString("水🪶", StandardCharsets.UTF_8);
        emit("utf8", utf8);
        HPacket utf8Replacement = new HPacket(7);
        utf8Replacement.appendString("cat", StandardCharsets.UTF_8).appendInt(42);
        utf8Replacement.setReadIndex(7);
        utf8Replacement.replaceString(6, "雪🐱", StandardCharsets.UTF_8);
        emit("utf8_replacement", utf8Replacement);
        HPacket utf16 = new HPacket(8);
        utf16.appendString("Aé水", StandardCharsets.UTF_16BE).appendInt(42);
        emit("utf16", utf16);
        utf16.setReadIndex(7);
        utf16.replaceString(6, "Z猫", StandardCharsets.UTF_16BE);
        emit("utf16_replacement", utf16);
        HPacket utf16Long = new HPacket(9);
        utf16Long.appendLongString("水🐱", StandardCharsets.UTF_16BE).appendInt(123);
        emit("utf16_long", utf16Long);
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
