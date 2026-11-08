package gearth.app.protocol.packethandler.flash;
import gearth.misc.listenerpattern.Observable;
import gearth.protocol.HMessage;
import gearth.app.protocol.TrafficListener;
import gearth.app.services.extension_handler.ExtensionHandler;
import java.io.IOException;
import java.io.OutputStream;
// Minimal superclass isolates the original identification method, not the transport.
public class FlashPacketHandler {
    private boolean dataStream;
    protected FlashPacketHandler(HMessage.Direction direction, OutputStream out, Observable<TrafficListener>[] listeners, ExtensionHandler extensions) {}
    public boolean isDataStream() { return dataStream; }
    public void setAsDataStream() { dataStream = true; }
    public void act(byte[] buffer) throws IOException {}
}
