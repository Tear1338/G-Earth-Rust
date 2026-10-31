import gearth.protocol.HPacket;
import gearth.protocol.HMessage;
import gearth.encoding.VL64Encoding;
import gearth.encoding.Base64Encoding;
import java.util.HexFormat;

// Uses the actual beta-29 API JAR, not a second hand-written packet codec.
public class JavaOracle {
    static void emit(String name, byte[] bytes) {System.out.println(name+"="+HexFormat.of().formatHex(bytes));}
    public static void main(String[] args) {
        HPacket basic=new HPacket(123,42,"hello",true);emit("basic",basic.toBytes());
        HPacket latin=new HPacket(255,"éÿ\0");emit("latin1",latin.toBytes());
        HPacket p=new HPacket(1);p.appendInt(Integer.MIN_VALUE);p.appendLong(Long.MAX_VALUE);p.appendDouble(-2.5);emit("numbers",p.toBytes());
        HPacket binary=new HPacket(8,new byte[]{0,9,(byte)128,(byte)255});
        HMessage message=new HMessage(binary,HMessage.Direction.TOCLIENT,42);message.setBlocked(true);
        emit("message",message.stringify().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        for(int n:new int[]{-1000000,-256,-4,-1,0,1,3,4,63,64,256,1000000,Integer.MAX_VALUE})emit("vl64_"+n,VL64Encoding.encode(n));
        emit("b64_123",Base64Encoding.encode(123,2));
    }
}
