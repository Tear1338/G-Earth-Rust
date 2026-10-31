import gearth.extensions.Extension;
import gearth.extensions.ExtensionInfo;
import gearth.protocol.HMessage;
import gearth.protocol.HPacket;

@ExtensionInfo(Title="Rust compatibility fixture",Description="Tests the actual beta-29 Extension base class",Version="1",Author="G-Earth Rust")
public class JavaExtensionFixture extends Extension {
    public JavaExtensionFixture(String[] args) {
        super(args);
        intercept(HMessage.Direction.TOSERVER,"TestOutgoing",message->{
            int value=message.getPacket().readInteger();
            if(value==13) message.setBlocked(true);
            else message.getPacket().replaceInt(6,value+1);
        });
        intercept(HMessage.Direction.TOCLIENT,78,message->message.getPacket().replaceInt(6,message.getPacket().readInteger()+2));
    }
    @Override public void onStartConnection() {
        sendToServer(new HPacket("TestInjection",HMessage.Direction.TOSERVER,17));
    }
    public static void main(String[] args) {new JavaExtensionFixture(args).run();}
}
