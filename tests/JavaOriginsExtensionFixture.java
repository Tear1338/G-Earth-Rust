import gearth.encoding.VL64Encoding;
import gearth.extensions.Extension;
import gearth.extensions.ExtensionInfo;
import gearth.protocol.HMessage;
import gearth.protocol.packethandler.shockwave.packets.ShockPacketOutgoing;
import gearth.protocol.packethandler.shockwave.packets.ShockPacketIncoming;

@ExtensionInfo(Title="Origins compatibility fixture", Description="Tests beta-29 WEDGIE interception", Version="1", Author="G-Earth Rust")
public class JavaOriginsExtensionFixture extends Extension {
    public JavaOriginsExtensionFixture(String[] args) {
        super(args);
        intercept(HMessage.Direction.TOSERVER, "Known", message -> {
            int value = message.getPacket().readInteger();
            if (value == 13) {
                message.setBlocked(true);
            } else if (value == 42) {
                message.getPacket().replaceBytes(2, VL64Encoding.encode(43));
                sendToServer(new ShockPacketOutgoing("Known", 18));
            }
        });
        intercept(HMessage.Direction.TOCLIENT, 78, message -> {
            if (message.getPacket().readString().equals("hello")) {
                message.getPacket().replaceByte(2, (byte) 'H');
                sendToClient(new ShockPacketIncoming("Incoming", "extra"));
            }
        });
    }
    @Override public void onStartConnection() {
        sendToServer(new ShockPacketOutgoing("Known", 17));
    }
    public static void main(String[] args) {
        new JavaOriginsExtensionFixture(args).run();
    }
}
