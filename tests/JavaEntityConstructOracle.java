import gearth.extensions.parsers.HEntity;
import gearth.protocol.HPacket;
import java.util.HexFormat;

public class JavaEntityConstructOracle {
    public static void main(String[] args) {
        HPacket input = new HPacket(1);
        input.appendInt(17).appendString("Bot").appendString("hello")
            .appendString("figure").appendInt(23).appendInt(3).appendInt(4)
            .appendString("1.5").appendInt(5).appendInt(3);
        HEntity entity = new HEntity(input);
        HPacket result = HEntity.constructPacket(new HEntity[]{entity, entity}, 42);
        System.out.println(HexFormat.of().formatHex(result.toBytes()));
    }
}
