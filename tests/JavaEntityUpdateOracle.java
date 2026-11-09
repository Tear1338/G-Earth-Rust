import gearth.extensions.parsers.HEntityUpdate;
import gearth.extensions.parsers.HPoint;
import gearth.protocol.HPacket;
import java.util.Locale;

public class JavaEntityUpdateOracle {
    public static void main(String[] args) {
        String[] cases = {"sit ", "lay  ", "flatctrl ", "mv 1,2,", "mv 0x-1,2,3", "sign -+1", "mv +0x1,-02,3", "sit  /sign 1", "mv 1,2,3,", "sign 0x1", "mv --1,2,3"};
        for (int i = 0; i < cases.length; i++) {
            HPacket packet = new HPacket(1);
            packet.appendInt(1).appendInt(7).appendInt(2).appendInt(3).appendString("1.0")
                .appendInt(0).appendInt(1).appendString(cases[i]);
            try {
                HEntityUpdate update = HEntityUpdate.parse(packet)[0];
                HPoint moving = update.getMovingTo();
                String coordinates = moving == null ? "none" : String.format(Locale.ROOT, "%d,%d,%.1f", moving.getX(), moving.getY(), moving.getZ());
                System.out.println("case_" + i + "=" + update.getAction() + ";" + update.getStance() + ";" + update.getSign() + ";" + update.isController() + ";" + coordinates);
            } catch (RuntimeException e) {
                System.out.println("case_" + i + "=error");
            }
        }
    }
}
