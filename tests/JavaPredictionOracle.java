import gearth.protocol.HPacket;
import gearth.protocol.HMessage;
import gearth.services.Constants;
import gearth.services.packet_info.PacketInfo;
import gearth.services.packet_info.PacketInfoManager;
import gearth.services.packet_representation.prediction.StructurePredictor;
import gearth.services.packet_representation.PacketStringUtils;
import java.util.HexFormat;

public class JavaPredictionOracle {
    public static void main(String[] args) {
        String[] samples = {"", "0000002a000568656c6c6f01", "ffffffff", "00000100", "61626364", "0000", "0100ffff", "0002c2a9", "0000000000bc614e", "000568656c6c6f00000000", "000000010000000000000001", "0020ff0001020304"};
        for (boolean unity : new boolean[]{false, true}) {
            Constants.UNITY_PACKETS = unity;
            for (int i=0; i<samples.length; i++) {
                HPacket packet = new HPacket(1, HexFormat.of().parseHex(samples[i]));
                System.out.println((unity ? "unity_" : "classic_") + i + "=" + new StructurePredictor(packet).getStructure());
                System.out.println((unity ? "expression_unity_" : "expression_classic_") + i + "=" + HexFormat.of().formatHex(PacketStringUtils.predictedExpression(packet, null).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
        }
        HPacket nested = new HPacket(1);
        nested.appendInt(2).appendString("a").appendInt(7).appendString("b\\\"").appendInt(-1);
        System.out.println("nested=" + HexFormat.of().formatHex(PacketStringUtils.toExpressionFromGivenStructure(nested, "i(si)", null).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        nested.setReadIndex(7);
        for (String structure : new String[]{"i(si)", "i(s)", "i(si)b", "", "i(", "i(si)?extra", "i(si))", "i(s?i)"}) {
            System.out.println("match_" + HexFormat.of().formatHex(structure.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "=" + nested.structureEquals(structure) + "," + nested.getReadIndex());
        }
        HPacket empty = new HPacket(1);
        System.out.println("match_empty=" + empty.structureEquals("") + "," + empty.getReadIndex());
        System.out.println("match_unknown_empty=" + empty.structureEquals("?ignored") + "," + empty.getReadIndex());
        HPacket numeric = new HPacket(1);
        numeric.appendFloat(0.1f).appendDouble(-2.5).appendShort((short) 8);
        System.out.println("numeric=" + HexFormat.of().formatHex(PacketStringUtils.toExpressionFromGivenStructure(numeric, "fdu", null).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        HPacket floats = new HPacket(1);
        floats.appendFloat(0.0001f).appendFloat(10000000f).appendDouble(0.0000001);
        System.out.println("floats=" + HexFormat.of().formatHex(PacketStringUtils.toExpressionFromGivenStructure(floats, "ffd", null).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        Constants.UNITY_PACKETS = false;
        HPacket named = new HPacket(42);
        named.appendInt(7).appendString("hello");
        PacketInfo withoutStructure = new PacketInfo(HMessage.Direction.TOCLIENT, 42, "hash0", "Earlier", null, "test");
        PacketInfo known = new PacketInfo(HMessage.Direction.TOCLIENT, 42, "hash1", "Known", "is", "test");
        PacketInfo wrongDirection = new PacketInfo(HMessage.Direction.TOSERVER, 42, "hash2", "Wrong", "b", "test");
        for (boolean structure : new boolean[]{true, false}) {
            PacketInfoManager manager = new PacketInfoManager("test", structure ? java.util.List.of(withoutStructure, known, wrongDirection) : java.util.List.of(withoutStructure, wrongDirection));
            String expression = named.toExpression(HMessage.Direction.TOCLIENT, manager, true);
            System.out.println((structure ? "named_known" : "named_predicted") + "=" + HexFormat.of().formatHex(expression.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
    }
}
