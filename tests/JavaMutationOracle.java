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
        String[][] nestedGroups = {
            {"(a\\.b) a.b", "(a\\.b)", "<$1>", "1"},
            {"((ab)c) abc", "((ab)c)", "$1/$2/$0", "-1"},
            {"a()b ab", "a()b", "<$1>", "1"},
            {"(a()) a", "(a())", "$1/$2", "1"},
            {"a(\\()b a(b", "a(\\()b", "[$1]", "1"},
            {"((ab)c)", "((ab)c)", "$3", "1"},
        };
        for (int i = 0; i < nestedGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(nestedGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(nestedGroups[i][1], nestedGroups[i][2], Integer.parseInt(nestedGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_nested_" + i + "=error");
            else emit("substring_nested_" + i, sample);
        }
        String[][] zeroGroups = {
            {"()", "()", "x", "1"},
            {"é()a", "()", "-", "1"},
            {"(())", "(())", "$1/$2", "1"},
            {"()", "()", "$2", "1"},
            {"abc", "()", "$2", "1"},
            {"()", "()", "$", "0"},
        };
        for (int i = 0; i < zeroGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(zeroGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(zeroGroups[i][1], zeroGroups[i][2], Integer.parseInt(zeroGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_zero_" + i + "=error");
            else emit("substring_zero_" + i, sample);
        }
        String[][] quotedGroups = {
            {"(\\Q(a+b)\\E) (a+b)", "(\\Q(a+b)\\E)", "[$1]", "1"},
            {"(\\Qx.y\\E) x.y", "(\\Qx.y\\E)", "$0:$1", "1"},
            {"(cat)\\Qx catx", "(cat)\\Qx", "<$1>", "1"},
            {"(\\Q\\E) x", "(\\Q\\E)", "-", "1"},
            {"(\\Q(a+b)\\E)", "(\\Q(a+b)\\E)", "$2", "1"},
        };
        for (int i = 0; i < quotedGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(quotedGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(quotedGroups[i][1], quotedGroups[i][2], Integer.parseInt(quotedGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_quoted_" + i + "=error");
            else emit("substring_quoted_" + i, sample);
        }
        String[][] namedGroups = {
            {"(?<pet>cat) cat", "(?<pet>cat)", "${pet}-$1-$0", "1"},
            {"(?<all>x(?<inner>y)) xy", "(?<all>x(?<inner>y))", "${inner}/${all}/$2", "1"},
            {"(?<empty>)", "(?<empty>)", "[${empty}]", "1"},
            {"(?<pet>cat) cat", "(?<pet>cat)", "${missing}", "1"},
            {"(?<pet>cat)", "(?<pet>cat)", "${missing}", "1"},
            {"(?<pet>cat) cat", "(?<pet>cat)", "${pet}0", "1"},
        };
        for (int i = 0; i < namedGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(namedGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(namedGroups[i][1], namedGroups[i][2], Integer.parseInt(namedGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_named_" + i + "=error");
            else emit("substring_named_" + i, sample);
        }
        String[][] dotGroups = {
            {"(c.t) cat cot c.t", "(c.t)", "[$1]", "1"},
            {"x(.)y xay xéy x\ny", "x(.)y", "$1:$0", "1"},
            {"(?<g>.) a\rb\nc\u0085d", "(?<g>.)", "${g}", "1"},
            {"x(.)y x\ny", "x(.)y", "$9", "1"},
            {"(c.t) cat", "(c.t)", "$2", "1"},
        };
        for (int i = 0; i < dotGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(dotGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(dotGroups[i][1], dotGroups[i][2], Integer.parseInt(dotGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_dot_" + i + "=error");
            else emit("substring_dot_" + i, sample);
        }
        String[] dotPatterns = {"(.)", "(a.)", "a(.)b", "(.)(.)", "(?<one>.)(?<two>.)"};
        char[] dotAlphabet = {'a', 'b', '.', '\n', '\r', '\u0085', 'é', '(', ')'};
        for (int i = 0; i < 120; i++) {
            String pattern = dotPatterns[i % dotPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 24; j++) value.append(dotAlphabet[(i * 7 + j * 5) % dotAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_dot_corpus_" + i, sample);
        }
        String[][] classGroups = {
            {"([abc]) a b c d", "([abc])", "<$1>", "1"},
            {"x([a-c])y xay xby xdy", "x([a-c])y", "$1:$0", "1"},
            {"([^a]) a é\n", "([^a])", "[$1]", "1"},
            {"([é-ÿ]) é ç z", "([é-ÿ])", "[$1]", "1"},
            {"([\\-\\]]) - ] a", "([\\-\\]])", "<$1>", "1"},
            {"([a-c]) abc", "([a-c])", "$2", "1"},
            {"x([a])y xby", "x([a])y", "$9", "1"},
        };
        for (int i = 0; i < classGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(classGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(classGroups[i][1], classGroups[i][2], Integer.parseInt(classGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_class_" + i + "=error");
            else emit("substring_class_" + i, sample);
        }
        String[] classPatterns = {"([abc])", "x([a-c])y", "([^a])", "([é-ÿ])", "([\\-\\]])"};
        char[] classAlphabet = {'a', 'b', 'c', 'd', 'x', 'y', 'é', 'ÿ', '-', ']', '\n', '\u0085'};
        for (int i = 0; i < 120; i++) {
            String pattern = classPatterns[i % classPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 28; j++) value.append(classAlphabet[(i * 7 + j * 5) % classAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_class_corpus_" + i, sample);
        }
        String[] predefinedPatterns = {"(\\d)", "(\\D)", "(\\w)", "(\\W)", "(\\s)", "(\\S)"};
        char[] predefinedAlphabet = {'a', 'Z', '0', '9', '_', 'é', 'ÿ', ' ', '\t', '\n', '\r', '\u000b', '\u000c', '\u0085'};
        for (int i = 0; i < 120; i++) {
            String pattern = predefinedPatterns[i % predefinedPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 28; j++) value.append(predefinedAlphabet[(i * 7 + j * 5) % predefinedAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_predefined_" + i, sample);
        }
        String[][] unions = {
            {"([\\dA-F]) a 2 B é", "([\\dA-F])", "<$1>", "1"},
            {"([^\\w]) a é 9 _", "([^\\w])", "[$1]", "1"},
            {"([\\s\\d]) a 2 \n", "([\\s\\d])", "<$1>", "1"},
            {"([\\D]) a 2 é", "([\\D])", "[$1]", "1"},
            {"([a-\\d]) a 2", "([a-\\d])", "x", "1"},
            {"([\\d-a]) a 2", "([\\d-a])", "x", "1"},
        };
        for (int i = 0; i < unions.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(unions[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(unions[i][1], unions[i][2], Integer.parseInt(unions[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_union_" + i + "=error");
            else emit("substring_union_" + i, sample);
        }
        String[] unionPatterns = {"([\\dA-F])", "([^\\w])", "([\\s\\d])", "([\\D])", "([\\d-a])"};
        char[] unionAlphabet = {'a', 'b', 'F', '9', '0', '_', 'é', '-', ' ', '\n', '\u000b', '\u0085'};
        for (int i = 0; i < 120; i++) {
            String pattern = unionPatterns[i % unionPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 28; j++) value.append(unionAlphabet[(i * 7 + j * 5) % unionAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_union_corpus_" + i, sample);
        }
        String[] controlPatterns = {"(\\n)", "([\\t\\x41])", "([\\u00e9])", "(\\a)", "(\\e)", "(\\f)", "([\\x30-\\x39])"};
        char[] controlAlphabet = {'a', 'A', '0', '9', 'é', 'ÿ', ' ', '\t', '\n', '\r', '\u0007', '\u001b', '\u000c'};
        for (int i = 0; i < 140; i++) {
            String pattern = controlPatterns[i % controlPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 28; j++) value.append(controlAlphabet[(i * 7 + j * 5) % controlAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_control_corpus_" + i, sample);
        }
        String[][] optionalGroups = {
            {"(a?) a ab", "(a?)", "[$1]", "1"},
            {"(a??) a ab", "(a??)", "[$1]", "1"},
            {"x(a?)b xb xab", "x(a?)b", "$1/$0", "1"},
            {"x(a??)b xb xab", "x(a??)b", "$1/$0", "1"},
            {"x(.?)b xéb x\nb", "x(.?)b", "[$1]", "1"},
            {"(\\d?) 1 2", "(\\d?)", "<$1>", "1"},
            {"(a?)", "(a?)", "$2", "1"},
        };
        for (int i = 0; i < optionalGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(optionalGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(optionalGroups[i][1], optionalGroups[i][2], Integer.parseInt(optionalGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_optional_" + i + "=error");
            else emit("substring_optional_" + i, sample);
        }
        String[] optionalPatterns = {"(a?)", "(a??)", "x(a?)b", "x(a??)b", "x(.?)b", "(\\d?)", "([a-c]?)"};
        char[] optionalAlphabet = {'a', 'b', 'c', 'x', '1', 'é', '-', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 140; i++) {
            String pattern = optionalPatterns[i % optionalPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(' ');
            for (int j = 0; j < 24; j++) value.append(optionalAlphabet[(i * 7 + j * 5) % optionalAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_optional_corpus_" + i, sample);
        }
        String[] backtrackPatterns = {"(a?ab)", "(a??ab)", "((a?)(b?))", "x(a?b??)c", "(?<both>a?b?)"};
        char[] backtrackAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 160; i++) {
            String pattern = backtrackPatterns[i % backtrackPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" ab aab ");
            for (int j = 0; j < 24; j++) value.append(backtrackAlphabet[(i * 7 + j * 5) % backtrackAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_backtrack_" + i, sample);
        }
        String[][] optionalCaptures = {
            {"(a)? a b", "(a)?", "[$1]", "1"},
            {"(a)?? a b", "(a)??", "[$1]", "1"},
            {"x(ab)?c xc xabc", "x(ab)?c", "$1/$0", "1"},
            {"x(ab)??c xc xabc", "x(ab)??c", "$1/$0", "1"},
            {"x((a)b)?c xc xabc", "x((a)b)?c", "$1/$2/$0", "1"},
            {"()? x", "()?", "[$1]", "1"},
            {"(a)?", "(a)?", "$2", "1"},
        };
        for (int i = 0; i < optionalCaptures.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(optionalCaptures[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(optionalCaptures[i][1], optionalCaptures[i][2], Integer.parseInt(optionalCaptures[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_optional_capture_" + i + "=error");
            else emit("substring_optional_capture_" + i, sample);
        }
        String[] optionalCapturePatterns = {"(a)?", "(a)??", "x(ab)?c", "x(ab)??ab", "x((a)b)?c", "(a)?(b)?", "()?"};
        char[] optionalCaptureAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 140; i++) {
            String pattern = optionalCapturePatterns[i % optionalCapturePatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" xc xabc xab ");
            for (int j = 0; j < 24; j++) value.append(optionalCaptureAlphabet[(i * 7 + j * 5) % optionalCaptureAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_optional_capture_corpus_" + i, sample);
        }
        String[] overlappingPatterns = {"((a?)b)?", "((a)?)?", "x((a?)b)??c", "((a?)(b?))?", "(?<all>(?<one>a?)b?)?"};
        char[] overlappingAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 160; i++) {
            String pattern = overlappingPatterns[i % overlappingPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" xc xabc xab ");
            for (int j = 0; j < 24; j++) value.append(overlappingAlphabet[(i * 7 + j * 5) % overlappingAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_overlapping_" + i, sample);
        }
        String[][] repeatGroups = {
            {"(a*) aaa b", "(a*)", "[$1]", "1"},
            {"(a*?) aaa b", "(a*?)", "[$1]", "1"},
            {"(a+) aaa b", "(a+)", "[$1]", "1"},
            {"(a+?) aaa b", "(a+?)", "[$1]", "1"},
            {"x(a*)ab xaab xab", "x(a*)ab", "$1/$0", "1"},
            {"x(a*?)ab xaab xab", "x(a*?)ab", "$1/$0", "1"},
            {"(\\d*) 123 a", "(\\d*)", "<$1>", "1"},
            {"(.+) a\nb", "(.+)", "[$1]", "1"},
        };
        for (int i = 0; i < repeatGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(repeatGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(repeatGroups[i][1], repeatGroups[i][2], Integer.parseInt(repeatGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_repeat_" + i + "=error");
            else emit("substring_repeat_" + i, sample);
        }
        String[] repeatPatterns = {"(a*)", "(a+?)", "x(a*)ab", "((a*)b)?", "x(\\d+)b", "((a*)b?)", "([ab]+)(a*)", "((a*)b*)"};
        char[] repeatAlphabet = {'a', 'b', 'c', 'x', '0', '1', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 160; i++) {
            String pattern = repeatPatterns[i % repeatPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" aaaa ab aaab xab xaab x123b ");
            for (int j = 0; j < 24; j++) value.append(repeatAlphabet[(i * 7 + j * 3) % repeatAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_repeat_corpus_" + i, sample);
        }
        String[][] boundedGroups = {
            {"(a{2}) a aaa", "(a{2})", "[$1]", "1"},
            {"(a{0}) a", "(a{0})", "[$1]", "1"},
            {"(a{1,3}) a aaaa", "(a{1,3})", "[$1]", "1"},
            {"(a{1,3}?) a aaaa", "(a{1,3}?)", "[$1]", "1"},
            {"x(a{2,}?)b xaab xaaab", "x(a{2,}?)b", "$1/$0", "1"},
            {"([a-c]{2,3}) abcd", "([a-c]{2,3})", "[$1]", "1"},
            {"(a{2,1}) aa", "(a{2,1})", "x", "1"},
            {"(a{2147483648}) aa", "(a{2147483648})", "x", "1"},
        };
        for (int i = 0; i < boundedGroups.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(boundedGroups[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(boundedGroups[i][1], boundedGroups[i][2], Integer.parseInt(boundedGroups[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_bounded_" + i + "=error");
            else emit("substring_bounded_" + i, sample);
        }
        String[] boundedPatterns = {"(a{0})", "(a{2})", "(a{1,3})", "(a{1,3}?)", "x(a{2,}?)b", "([a-c]{2,3})", "((a{1,2})b)?", "x(\\d{1,2})b"};
        char[] boundedAlphabet = {'a', 'b', 'c', 'x', '0', '1', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 160; i++) {
            String pattern = boundedPatterns[i % boundedPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" aaaa ab aaab xab xaab x123b ");
            for (int j = 0; j < 24; j++) value.append(boundedAlphabet[(i * 7 + j * 3) % boundedAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_bounded_corpus_" + i, sample);
        }
        String[][] repeatedCaptures = {
            {"(ab)* abab x", "(ab)*", "[$1]", "1"},
            {"(ab)+? ababab", "(ab)+?", "[$1]", "1"},
            {"((a)?b)* abb ab", "((a)?b)*", "$1/$2", "1"},
            {"x((a)?b)+c xabbc", "x((a)?b)+c", "$1/$2/$0", "1"},
            {"(a*)* aa", "(a*)*", "[$1]", "1"},
            {"(ab){2,3} abababab", "(ab){2,3}", "<$1>", "1"},
            {"(a?)* a", "(a?)*", "[$1]", "1"},
        };
        for (int i = 0; i < repeatedCaptures.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(repeatedCaptures[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(repeatedCaptures[i][1], repeatedCaptures[i][2], Integer.parseInt(repeatedCaptures[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_repeated_capture_" + i + "=error");
            else emit("substring_repeated_capture_" + i, sample);
        }
        String[] simpleRepeatGroupPatterns = {"(ab)*", "(ab)+?", "x(ab)*ab", "x([ab]){1,3}b", "(?<v>ab)+?", "(ab){0,2}"};
        char[] simpleRepeatGroupAlphabet = {'a', 'b', 'c', 'x', '0', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 150; i++) {
            String pattern = simpleRepeatGroupPatterns[i % simpleRepeatGroupPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abab ababab xabab xab ");
            for (int j = 0; j < 20; j++) value.append(simpleRepeatGroupAlphabet[(i * 7 + j * 3) % simpleRepeatGroupAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_simple_repeat_group_" + i, sample);
        }
        java.util.regex.Matcher retainedCapture = java.util.regex.Pattern.compile("((a)?b)*").matcher("abb");
        if (!retainedCapture.matches()) throw new AssertionError("expected repeated-group match");
        System.out.println("repeated_capture_retention=" + retainedCapture.group(1) + "," + retainedCapture.group(2));
        String[] fixedNestedPatterns = {"((a)b)*", "(x(?<inner>y))+", "((a)(b)){1,3}", "x((a)b)*c", "(((ab)))+"};
        char[] fixedNestedAlphabet = {'a', 'b', 'c', 'x', 'y', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 150; i++) {
            String pattern = fixedNestedPatterns[i % fixedNestedPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abab xyxy xabc ");
            for (int j = 0; j < 20; j++) value.append(fixedNestedAlphabet[(i * 7 + j * 3) % fixedNestedAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_fixed_nested_repeat_" + i, sample);
        }
        String[] retentionPatterns = {"((a)?b)*", "((a)??b)*", "x((a)?b)+c", "((a)?b)*?", "((a)?b)+?", "((a)?b)*b", "((?<inner>a)?b)*ab", "((a)?b)+ab"};
        char[] retentionAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 200; i++) {
            String pattern = retentionPatterns[i % retentionPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abb abbb xabbc bbb ab ");
            for (int j = 0; j < 20; j++) value.append(retentionAlphabet[(i * 7 + j * 3) % retentionAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_retention_corpus_" + i, sample);
        }
        String[] multiRetentionPatterns = {"((a)?(b)?c)*", "((a)??(b)?c)*", "x((a)?(b)??c)+d", "((?<left>a)?(?<right>b)?c)*c", "((a)?x(b)?c)+?"};
        char[] multiRetentionAlphabet = {'a', 'b', 'c', 'd', 'x', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 200; i++) {
            String pattern = multiRetentionPatterns[i % multiRetentionPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" ac bc c abc xacbcd ");
            for (int j = 0; j < 20; j++) value.append(multiRetentionAlphabet[(i * 7 + j * 3) % multiRetentionAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$3/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_multi_retention_" + i, sample);
        }
        String[] nullablePatterns = {"((a)?(b)?)*", "((a)?(b)?)*?", "((a)??(b)?)+", "x((a)?(b)?)*b", "((?<left>a)?(?<right>b)?)+?", "x((a)?(b)??)+b"};
        char[] nullableAlphabet = {'a', 'b', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 180; i++) {
            String pattern = nullablePatterns[i % nullablePatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" ab aa bb xab xb ");
            for (int j = 0; j < 16; j++) value.append(nullableAlphabet[(i * 7 + j * 3) % nullableAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$3/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_nullable_repeat_" + i, sample);
        }
        String[][] boundedNested = {
            {"((a)?b){2} abb ab", "((a)?b){2}", "$1/$2/$0", "1"},
            {"((a)?b){1,3} abbb", "((a)?b){1,3}", "$1/$2/$0", "1"},
            {"((a)?b){1,3}? abbb", "((a)?b){1,3}?", "$1/$2/$0", "1"},
            {"((a)?b){2,} abb ab", "((a)?b){2,}", "$1/$2/$0", "1"},
            {"((a)?(b)?){2,4} ab", "((a)?(b)?){2,4}", "$1/$2/$3/$0", "1"},
            {"((a)?(b)?){2,4}? ab", "((a)?(b)?){2,4}?", "$1/$2/$3/$0", "1"},
            {"((a)?b){0} ab", "((a)?b){0}", "$1/$2/$0", "1"},
        };
        for (int i = 0; i < boundedNested.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(boundedNested[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(boundedNested[i][1], boundedNested[i][2], Integer.parseInt(boundedNested[i][3]));
            } finally { System.setOut(original); }
            emit("substring_bounded_nested_" + i, sample);
        }
        String[] boundedNestedPatterns = {"((a)?b){2}", "((a)?b){1,3}", "((a)?b){1,3}?", "((a)?b){2,}", "((a)?(b)?){2,4}", "((a)?(b)?){2,4}?", "((a)?b){0}"};
        char[] boundedNestedAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 140; i++) {
            String pattern = boundedNestedPatterns[i % boundedNestedPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abb abbb ab bb a ");
            for (int j = 0; j < 16; j++) value.append(boundedNestedAlphabet[(i * 7 + j * 3) % boundedNestedAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_bounded_nested_corpus_" + i, sample);
        }
        String[] innerRepeatPatterns = {"((a*)?b)*", "((a+)?b)*", "((a{1,3})?b){2,3}", "((a+?)?b)*?", "x((a*)?b)+c", "(a*)*"};
        char[] innerRepeatAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 180; i++) {
            String pattern = innerRepeatPatterns[i % innerRepeatPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abb aaab b xabbc ");
            for (int j = 0; j < 16; j++) value.append(innerRepeatAlphabet[(i * 7 + j * 3) % innerRepeatAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, pattern.equals("(a*)*") ? "$1/$0" : "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_inner_repeat_" + i, sample);
        }
        String[] optionalAtomPatterns = {"(a?)*", "(a??)*", "([ab]?)+", "(a?b?)*", "x(a?b?){2,3}c", "((a)?b?)*"};
        char[] optionalAtomAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 180; i++) {
            String pattern = optionalAtomPatterns[i % optionalAtomPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" ab aa bb xabc ");
            for (int j = 0; j < 16; j++) value.append(optionalAtomAlphabet[(i * 7 + j * 3) % optionalAtomAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_optional_atom_repeat_" + i, sample);
        }
        String[] requiredInnerPatterns = {"((a?)b)*", "((a??)b)*", "((a?)?b)*", "((a?)(b?)c)*", "(x(a?)y(b?)z)+", "((a*)b)*", "((a+?)b){1,3}"};
        char[] requiredInnerAlphabet = {'a', 'b', 'c', 'x', 'y', 'z', 'é', ' ', '\n', '\u0085'};
        for (int i = 0; i < 210; i++) {
            String pattern = requiredInnerPatterns[i % requiredInnerPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" ab bb abc xyz ");
            for (int j = 0; j < 16; j++) value.append(requiredInnerAlphabet[(i * 7 + j * 3) % requiredInnerAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_required_inner_" + i, sample);
        }
        String[] deepPatterns = {"(((a)?)b)*", "((((a)?)?)b)*", "x(((a)?)b)+c", "(((a)?)b){2,3}?", "(((a*)?)b)*", "(((a)?)(b)?c)*"};
        char[] deepAlphabet = {'a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 180; i++) {
            String pattern = deepPatterns[i % deepPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" abb abbb xabbc bb ");
            for (int j = 0; j < 16; j++) value.append(deepAlphabet[(i * 7 + j * 3) % deepAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$2/$3/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_deep_capture_" + i, sample);
        }
        String maximumDepthPattern = "(".repeat(99) + "a?" + ")".repeat(99) + "*";
        HPacket maximumDepth = new HPacket(9);
        maximumDepth.appendString(maximumDepthPattern + " a");
        maximumDepth.setReadIndex(7);
        java.io.PrintStream beforeDepth = System.out;
        try {
            System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
            maximumDepth.replaceXSubstrings(maximumDepthPattern, "$99", 1);
        } finally { System.setOut(beforeDepth); }
        emit("substring_maximum_depth", maximumDepth);
        String[][] anchors = {
            {"a ^(a)", "^(a)"},
            {"a \\A(a)", "\\A(a)"},
            {"(a)$a\n", "(a)$"},
            {"(a)$a\r\n", "(a)$"},
            {"(a)\\Za\u0085", "(a)\\Z"},
            {"(a)\\za", "(a)\\z"},
            {"x($)", "x($)"},
            {"(^) value", "(^)"},
            {"(\\z) value", "(\\z)"},
            {"(a)$a\r", "(a)$"},
        };
        for (int i = 0; i < anchors.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(anchors[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(anchors[i][1], "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_anchor_" + i, sample);
        }
        String[] anchorPatterns = {"^(a)", "\\A(a)", "(a)$", "(a)\\z", "(a)\\Z", "(.)$", "(^)", "(\\z)"};
        String[] anchorSuffixes = {"", "\n", "\r\n", "\r", "\u0085", "b"};
        for (int i = 0; i < 144; i++) {
            String pattern = anchorPatterns[i % anchorPatterns.length];
            String value = "a " + pattern + " a" + anchorSuffixes[(i / anchorPatterns.length) % anchorSuffixes.length];
            HPacket sample = new HPacket(9);
            sample.appendString(value);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_anchor_corpus_" + i, sample);
        }
        String[] wordBoundaryPatterns = {"(\\b)", "(\\B)", "\\b(a)", "\\B(a)", "(a)\\b", "(\\b)(a)", "\\b(\\w+)\\b"};
        char[] wordBoundaryAlphabet = {'a', 'b', '0', '_', 'é', 'ÿ', '!', ' ', '\n', '\u0085'};
        for (int i = 0; i < 175; i++) {
            String pattern = wordBoundaryPatterns[i % wordBoundaryPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" éa _a 9é ! ");
            for (int j = 0; j < 16; j++) value.append(wordBoundaryAlphabet[(i * 7 + j * 3) % wordBoundaryAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_word_boundary_" + i, sample);
        }
        String[] insensitivePatterns = {"(?i)(cat)", "(?i)([a-c]+)", "(?i)([^a])", "(?i)(é)", "(?i)(\\x41)", "(?i)(\\QAb\\E)", "(?i)((a)?b)*"};
        char[] insensitiveAlphabet = {'a', 'A', 'b', 'B', 'C', 'é', 'É', '_', ' ', '\n', '\u0085'};
        for (int i = 0; i < 175; i++) {
            String pattern = insensitivePatterns[i % insensitivePatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" CAT cat ABC abc É é AB ab ");
            for (int j = 0; j < 16; j++) value.append(insensitiveAlphabet[(i * 7 + j * 3) % insensitiveAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_insensitive_" + i, sample);
        }
        String[][] noCapture = {
            {"cat cat", "cat", "[$0]", "1"},
            {"cat cat", "cat", "$1", "1"},
            {"cat cat", "dog", "$1", "1"},
            {"abc", "", "x", "1"},
            {"éa", "", "-", "1"},
            {"abc", "", "$0", "1"},
            {"abc", "", "$1", "1"},
            {"(?i)cat CAT cat", "(?i)cat", "[$0]", "1"},
            {".abc.", ".", "[$0]", "1"},
            {"abc", "", "$", "0"},
        };
        for (int i = 0; i < noCapture.length; i++) {
            HPacket sample = new HPacket(9);
            sample.appendString(noCapture[i][0]);
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            boolean failed = false;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(noCapture[i][1], noCapture[i][2], Integer.parseInt(noCapture[i][3]));
            } catch (RuntimeException expected) { failed = true; }
            finally { System.setOut(original); }
            if (failed) System.out.println("substring_no_capture_" + i + "=error");
            else emit("substring_no_capture_" + i, sample);
        }
        String[] dotallPatterns = {"(?s)(.)", "(?s)(.+)", "(?s).", "(?is)(a.b)", "(?si)([a-c].)", "(?i)(?s)(a.)", "(?s)((a)?.)*"};
        char[] dotallAlphabet = {'a', 'A', 'b', 'B', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 175; i++) {
            String pattern = dotallPatterns[i % dotallPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" a\nb A\rB ");
            for (int j = 0; j < 16; j++) value.append(dotallAlphabet[(i * 7 + j * 3) % dotallAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, pattern.equals("(?s).") ? "$0" : "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_dotall_" + i, sample);
        }
        String[] multilinePatterns = {"(?m)^(a)", "(?m)(a)$", "(?m)\\A(a)", "(?m)(a)\\Z", "(?m)(a)\\z", "(?im)^(a)", "(?ms)(.)$", "(?m)(^)"};
        char[] multilineAlphabet = {'a', 'A', 'b', 'é', ' ', '\n', '\r', '\u0085'};
        for (int i = 0; i < 200; i++) {
            String pattern = multilinePatterns[i % multilinePatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" a\r\na\nA\r\u0085a ");
            for (int j = 0; j < 16; j++) value.append(multilineAlphabet[(i * 7 + j * 3) % multilineAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_multiline_" + i, sample);
        }
        String[] unicodePatterns = {"(?iu)(é)", "(?iu)([é])", "(?iu)([^é])", "(?ui)([À-Ö]+)", "(?i)(?u)([ø-þ]+)", "(?iu)([a-z]+)", "(?u)(é)"};
        char[] unicodeAlphabet = {'é', 'É', 'à', 'À', 'ß', 'ÿ', '×', 'Ø', 'ø', 'Ð', 'ð', 'a', 'A'};
        for (int i = 0; i < 210; i++) {
            String pattern = unicodePatterns[i % unicodePatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" éÉàÀ Øø Ðð ");
            for (int j = 0; j < 16; j++) value.append(unicodeAlphabet[(i * 7 + j * 3) % unicodeAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_unicode_case_" + i, sample);
        }
        String[] unicodeClassPatterns = {"(?U)(\\w+)", "(?U)(\\W+)", "(?U)(\\s+)", "(?U)(\\S+)", "(?U)(\\d+)", "(?U)([\\w]+)", "(?U)([^\\w]+)", "(?U)(\\b)", "(?U)(\\B)", "(?iU)(é)"};
        char[] unicodeClassAlphabet = {'é', 'É', 'µ', 'ª', 'º', '×', '9', ' ', '\u0085', '\u00a0', 'a', '_'};
        for (int i = 0; i < 200; i++) {
            String pattern = unicodeClassPatterns[i % unicodeClassPatterns.length];
            StringBuilder value = new StringBuilder(pattern).append(" éÉ µªº 9_ ");
            for (int j = 0; j < 16; j++) value.append(unicodeClassAlphabet[(i * 7 + j * 3) % unicodeClassAlphabet.length]);
            HPacket sample = new HPacket(9);
            sample.appendString(value.toString());
            sample.setReadIndex(7);
            java.io.PrintStream original = System.out;
            try {
                System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
                sample.replaceXSubstrings(pattern, "$1/$0", 1);
            } finally { System.setOut(original); }
            emit("substring_unicode_class_" + i, sample);
        }
        for (String kind : new String[]{"b", "B"}) {
            var pattern = java.util.regex.Pattern.compile("\\" + kind, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
            byte[] matches = new byte[32];
            for (int value = 0; value < 256; value++) {
                var matcher = pattern.matcher(Character.toString((char) value));
                if (matcher.find() && matcher.start() == 0) matches[value / 8] |= (byte) (1 << (value % 8));
            }
            System.out.println("unicode_class_" + kind + "=" + java.util.HexFormat.of().formatHex(matches));
        }
        for (String kind : new String[]{"d", "D", "w", "W", "s", "S"}) {
            var pattern = java.util.regex.Pattern.compile("\\" + kind, java.util.regex.Pattern.UNICODE_CHARACTER_CLASS);
            byte[] matches = new byte[32];
            for (int value = 0; value < 256; value++) {
                if (pattern.matcher(Character.toString((char) value)).matches()) matches[value / 8] |= (byte) (1 << (value % 8));
            }
            System.out.println("unicode_class_" + kind + "=" + java.util.HexFormat.of().formatHex(matches));
        }
        for (int first = 0; first < 256; first++) {
            var pattern = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(Character.toString((char) first)),
                java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE);
            byte[] matches = new byte[32];
            for (int second = 0; second < 256; second++) {
                if (pattern.matcher(Character.toString((char) second)).matches()) matches[second / 8] |= (byte) (1 << (second % 8));
            }
            System.out.println("unicode_case_" + first + "=" + java.util.HexFormat.of().formatHex(matches));
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
