import gearth.protocol.HPacket;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;

public class JavaMutationOracle {
    static void emit(String name, HPacket packet) {
        System.out.println(name + "=" + HexFormat.of().formatHex(packet.toBytes()) + "," + packet.getReadIndex());
    }
    public static void main(String[] args) {
        String[] malformedCases = {"eda080", "eda041", "eda0", "eda0ff", "edbf80", "ed9f80", "f0808080", "e08080", "f4908080", "e282", "e28241", "c080", "80"};
        for (int i = 0; i < malformedCases.length; i++) {
            byte[] bytes = HexFormat.of().parseHex(malformedCases[i]);
            HPacket p = new HPacket(18);
            p.appendUShort(bytes.length).appendBytes(bytes);
            System.out.println("utf8_case_" + i + "=" + HexFormat.of().formatHex(p.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));
        }
        // Exhaust every two-byte combination, then exercise mixed data and short-field boundaries.
        for (int first = 0; first < 256; first++) {
            for (int second = 0; second < 256; second++) {
                HPacket p = new HPacket(18);
                p.appendUShort(2).appendBytes(new byte[]{(byte) first, (byte) second});
                System.out.println("utf8_pair_" + (first * 256 + second) + "=" + HexFormat.of().formatHex(p.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));
            }
        }
        for (int length : new int[]{0, 1, 255, 256, 32767, 65535}) {
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++) bytes[i] = new byte[]{0x61, (byte) 0xed, (byte) 0xa0, (byte) 0x80, (byte) 0xc3, (byte) 0xa9, (byte) 0xff}[i % 7];
            HPacket p = new HPacket(18);
            p.appendUShort(length).appendBytes(bytes);
            System.out.println("utf8_length_" + length + "=" + HexFormat.of().formatHex(p.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));
        }
        // Deterministic mixed byte strings cover longer sequences without random CI failures.
        int state = 0x12345678;
        for (int caseIndex = 0; caseIndex < 20000; caseIndex++) {
            byte[] bytes = new byte[3 + caseIndex % 10];
            for (int i = 0; i < bytes.length; i++) {
                state ^= state << 13;
                state ^= state >>> 17;
                state ^= state << 5;
                bytes[i] = (byte) state;
            }
            HPacket p = new HPacket(18);
            p.appendUShort(bytes.length).appendBytes(bytes);
            System.out.println("utf8_mixed_" + caseIndex + "=" + HexFormat.of().formatHex(p.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));
        }
        int boundaryIndex = 0;
        int[] tails = {0x00, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xff};
        for (int lead : new int[]{0xe0, 0xed, 0xf0, 0xf4}) {
            for (int second = 0; second < 256; second++) {
                for (int third : tails) {
                    int[] fourths = lead < 0xf0 ? new int[]{-1} : tails;
                    for (int fourth : fourths) {
                        byte[] bytes = fourth < 0 ? new byte[]{(byte)lead, (byte)second, (byte)third} : new byte[]{(byte)lead, (byte)second, (byte)third, (byte)fourth};
                        HPacket p = new HPacket(18);
                        p.appendUShort(bytes.length).appendBytes(bytes);
                        System.out.println("utf8_boundary_" + boundaryIndex++ + "=" + HexFormat.of().formatHex(p.readString(6, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8)));
                    }
                }
            }
        }
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
        HPacket objects = new HPacket(19);
        objects.appendObjects((byte)-42, (short)-1234, -123456, -9000000000L, -3.25f, 0.125d, true, "Café");
        objects.setReadIndex(7);
        emit("append_objects", objects);
        HPacket latin1Java = new HPacket(20);
        latin1Java.appendString("Aé雪🐱B").appendLongString("水🪶é").appendInt(42);
        latin1Java.setReadIndex(7);
        emit("latin1_java", latin1Java);
        latin1Java.replaceString(6, "🐱雪é");
        emit("latin1_java_replaced", latin1Java);
        StringBuilder scalarChunk = new StringBuilder();
        int scalarIndex = 0;
        for (int codepoint = 0; codepoint <= 0x10ffff; codepoint++) {
            if (codepoint >= 0xd800 && codepoint <= 0xdfff) continue;
            scalarChunk.appendCodePoint(codepoint);
            if (++scalarIndex % 4096 == 0) {
                HPacket sample = new HPacket(21);
                sample.appendString(scalarChunk.toString());
                emit("latin1_scalar_" + (scalarIndex / 4096 - 1), sample);
                scalarChunk.setLength(0);
            }
        }
        if (scalarChunk.length() != 0) {
            HPacket sample = new HPacket(21);
            sample.appendString(scalarChunk.toString());
            emit("latin1_scalar_" + (scalarIndex / 4096), sample);
        }
        for (int length : new int[]{65535, 65536}) {
            HPacket sample = new HPacket(22);
            sample.appendString("🐱".repeat(length));
            emit("latin1_limit_" + length, sample);
        }
        String[] utf16Malformed = {"d8000041", "d800d800dc00", "dc00", "d800", "d80000", "004100", "dc00dc00", "d800dc00", "feff0041", "fffe0041"};
        for (int i = 0; i < utf16Malformed.length; i++) {
            byte[] bytes = HexFormat.of().parseHex(utf16Malformed[i]);
            HPacket sample = new HPacket(23);
            sample.appendUShort(bytes.length).appendBytes(bytes);
            System.out.println("utf16_case_" + i + "=" + HexFormat.of().formatHex(sample.readString(6, StandardCharsets.UTF_16BE).getBytes(StandardCharsets.UTF_8)));
        }
        for (int unit = 0; unit <= 0xffff; unit++) {
            HPacket sample = new HPacket(23);
            sample.appendUShort(2).appendShort((short)unit);
            System.out.println("utf16_unit_" + unit + "=" + HexFormat.of().formatHex(sample.readString(6, StandardCharsets.UTF_16BE).getBytes(StandardCharsets.UTF_8)));
        }
        java.util.Random utf16Random = new java.util.Random(1234);
        for (int i = 0; i < 10000; i++) {
            byte[] bytes = new byte[1 + i % 9];
            utf16Random.nextBytes(bytes);
            HPacket sample = new HPacket(23);
            sample.appendUShort(bytes.length).appendBytes(bytes);
            System.out.println("utf16_random_" + i + "=" + HexFormat.of().formatHex(bytes) + "," + HexFormat.of().formatHex(sample.readString(6, StandardCharsets.UTF_16BE).getBytes(StandardCharsets.UTF_8)));
        }
        String[] utf16Variants = {"", "A", "🐱", "\ufeffA"};
        for (int i = 0; i < utf16Variants.length; i++) {
            HPacket le = new HPacket(24);
            le.appendString(utf16Variants[i], StandardCharsets.UTF_16LE).appendLongString(utf16Variants[i], StandardCharsets.UTF_16LE);
            emit("utf16le_encoded_" + i, le);
            HPacket bom = new HPacket(24);
            bom.appendString(utf16Variants[i], StandardCharsets.UTF_16).appendLongString(utf16Variants[i], StandardCharsets.UTF_16);
            emit("utf16bom_encoded_" + i, bom);
        }
        String[] utf16Special = {"", "feff0041", "fffe4100", "0041", "4100", "fffe410000", "d8000041", "00d84100", "fefefffe0041"};
        for (int i = 0; i < utf16Special.length + 10000; i++) {
            byte[] bytes;
            if (i < utf16Special.length) bytes = HexFormat.of().parseHex(utf16Special[i]);
            else { bytes = new byte[1 + i % 9]; utf16Random.nextBytes(bytes); }
            HPacket sample = new HPacket(24);
            sample.appendUShort(bytes.length).appendBytes(bytes);
            System.out.println("utf16variant_" + i + "=" + HexFormat.of().formatHex(bytes) + "," + HexFormat.of().formatHex(sample.readString(6, StandardCharsets.UTF_16LE).getBytes(StandardCharsets.UTF_8)) + "," + HexFormat.of().formatHex(sample.readString(6, StandardCharsets.UTF_16).getBytes(StandardCharsets.UTF_8)));
        }
        char[][] selectedSurrogates = {{'\ud800'}, {'\udc00'}, {'\ud800','A'}, {'\ud800','\ud800','\udc00'}, {'\ud800','\udc00'}, {'A','\ud800','B'}, {}};
        java.util.Random unitRandom = new java.util.Random(9881);
        for (int i = 0; i < selectedSurrogates.length + 4096; i++) {
            char[] units;
            if (i < selectedSurrogates.length) units = selectedSurrogates[i];
            else { units = new char[1 + i % 8]; for (int j = 0; j < units.length; j++) units[j] = (char) unitRandom.nextInt(65536); }
            String text = new String(units);
            StringBuilder input = new StringBuilder();
            for (char unit : units) input.append(HexFormat.of().toHexDigits(unit));
            StringBuilder line = new StringBuilder("java_units_" + i + "=" + input);
            for (java.nio.charset.Charset charset : new java.nio.charset.Charset[]{StandardCharsets.ISO_8859_1, StandardCharsets.UTF_8, StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16}) line.append(',').append(HexFormat.of().formatHex(text.getBytes(charset)));
            System.out.println(line);
        }
        for (int length : new int[]{65535, 65536}) {
            HPacket sample = new HPacket(25);
            sample.appendString("a".repeat(length), StandardCharsets.UTF_8);
            emit("utf8_limit_" + length, sample);
        }
        HPacket utf8Multibyte = new HPacket(25);
        utf8Multibyte.appendString("€".repeat(21845), StandardCharsets.UTF_8);
        emit("utf8_limit_multibyte", utf8Multibyte);
        java.nio.charset.Charset[] utf16Charsets = {StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16};
        String invalidUnits = new String(new char[]{'A', '\ud800', 'B', '\udc00', '\ud800', '\udc00'});
        for (int i = 0; i < utf16Charsets.length; i++) {
            HPacket replacement = new HPacket(26);
            replacement.appendString("cat", utf16Charsets[i]).appendInt(42);
            replacement.setReadIndex(7);
            replacement.replaceString(6, invalidUnits, utf16Charsets[i]);
            emit("utf16_units_replace_" + i, replacement);
            HPacket longPacket = new HPacket(26);
            longPacket.appendLongString("a".repeat(32768), utf16Charsets[i]);
            emit("utf16_units_long_" + i, longPacket);
            for (int length : new int[]{32766, 32767, 32768}) {
                HPacket shortPacket = new HPacket(26);
                shortPacket.appendString("a".repeat(length), utf16Charsets[i]);
                emit("utf16_short_" + i + "_" + length, shortPacket);
            }
        }
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
        String[] templates = {"x$0y", "\\$", "\\\\", "$00", "$01", "$1", "$", "\\", "$$", "a\\qb"};
        for (int i = 0; i < templates.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString("cat cat").appendString("catdog");
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings("cat", templates[i], 1);
            } catch (RuntimeException e) {
                failed = true;
            } finally {
                System.setOut(original);
            }
            if (failed) System.out.println("substring_template_" + i + "=error");
            else emit("substring_template_" + i, sample);
        }
        String[][] groups = {
            {"(cat) cat", "(cat)", "[$1]", "1"},
            {"(cat) cat", "(cat)", "$0/$1/$01/$10", "-1"},
            {"(cat) cat", "(cat)", "\\$\\\\", "1"},
            {"(cat) cat", "(cat)", "$2", "1"},
            {"cat cat", "(cat)", "$2", "1"},
            {"(a) aaaa", "(a)", "x", "-1"},
            {"(é) é", "(é)", "[$1]", "1"},
            {"(cat) cat", "(cat)", "$", "0"},
        };
        for (int i = 0; i < groups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(groups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(groups[i][1], groups[i][2], Integer.parseInt(groups[i][3]));
            } catch (RuntimeException expected) {
                failed = true;
            } finally {
                System.setOut(original);
            }
            if (failed) System.out.println("substring_group_" + i + "=error");
            else emit("substring_group_" + i, sample);
        }
        String[][] multiGroups = {
            {"a(b)c abc", "a(b)c", "[$0:$1]", "-1"},
            {"a(b)c", "a(b)c", "$2", "1"},
            {"a(b)c abc", "a(b)c", "$2", "1"},
            {"(ab)(cd) abcd", "(ab)(cd)", "$2-$1-$0-$12", "1"},
            {"x(a)y(b)z xaybz", "x(a)y(b)z", "$01/$02/$00", "-1"},
            {"x(a)y(b)z", "x(a)y(b)z", "\\$", "1"},
            {"ordinary text", "a(b)c", "$2", "1"},
            {"a(b)c abc", "a(b)c", "$", "0"},
        };
        for (int i = 0; i < multiGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(multiGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(multiGroups[i][1], multiGroups[i][2], Integer.parseInt(multiGroups[i][3]));
            } catch (RuntimeException expected) {
                failed = true;
            } finally { System.setOut(original); }
            if (failed) System.out.println("substring_multi_" + i + "=error");
            else emit("substring_multi_" + i, sample);
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
