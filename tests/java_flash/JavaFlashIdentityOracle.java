import gearth.app.protocol.packethandler.flash.OutgoingFlashPacketHandler;
import gearth.protocol.HPacket;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.Arrays;

public class JavaFlashIdentityOracle {
    public static void main(String[] args) throws Exception {
        Method check = OutgoingFlashPacketHandler.class.getDeclaredMethod("dataStreamCheck", byte[].class);
        check.setAccessible(true);
        for (int i = 0; i < 3; i++) {
            HPacket packet = new HPacket(1);
            packet.appendString(i == 2 ? "" : "TEST-2026").appendString("FLASH");
            if (i == 1) packet.appendByte((byte) 42);
            OutgoingFlashPacketHandler handler = new OutgoingFlashPacketHandler(new ByteArrayOutputStream(), null, null);
            final String[] identity = {"none"};
            handler.addOnDatastreamConfirmedListener((version, identifier) -> identity[0] = version + "," + identifier);
            check.invoke(handler, (Object) packet.toBytes());
            System.out.println("identity_" + i + "=" + identity[0]);
        }
        HPacket hello = new HPacket(1);
        hello.appendString("TEST-2026").appendString("FLASH");
        byte[] bytes = hello.toBytes();
        for (int split = 1; split < bytes.length; split++) {
            OutgoingFlashPacketHandler handler = new OutgoingFlashPacketHandler(new ByteArrayOutputStream(), null, null);
            final String[] identity = {"none"};
            handler.addOnDatastreamConfirmedListener((version, identifier) -> identity[0] = version + "," + identifier);
            String status = "ok";
            try {
                handler.act(Arrays.copyOfRange(bytes, 0, split));
                handler.act(Arrays.copyOfRange(bytes, split, bytes.length));
            } catch (RuntimeException e) {
                status = e.getClass().getSimpleName();
            }
            System.out.println("split_" + split + "=" + status + "," + handler.isDataStream() + "," + identity[0]);
        }
    }
}
