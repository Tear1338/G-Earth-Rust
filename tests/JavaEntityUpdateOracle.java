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
        String[] heights = {"1.25", " 1.25 ", "1.25f", "-0.0D", "+Infinity", "NaN", "nan", "inf", "0x1.8p1", "-0X1p-1074", "0x1.00000000000008p0", "0x1p1024", "0x1p-1075", "0x1.8p-1075", "0x1p0f", "0x1", "1_0", "1e309"};
        for (int i = 0; i < heights.length; i++) {
            HPacket packet = new HPacket(1);
            packet.appendInt(1).appendInt(7).appendInt(2).appendInt(3).appendString(heights[i])
                .appendInt(0).appendInt(1).appendString("");
            try {
                double height = HEntityUpdate.parse(packet)[0].getTile().getZ();
                System.out.println("height_" + i + "=" + Long.toHexString(Double.doubleToRawLongBits(height)));
            } catch (RuntimeException e) {
                System.out.println("height_" + i + "=error");
            }
        }
        java.util.Random random = new java.util.Random(1234567);
        String alphabet = "0123456789abcdef";
        for (int i = 0; i < 3000; i++) {
            int count = 1 + random.nextInt(50);
            int dot = random.nextInt(count + 1);
            StringBuilder value = new StringBuilder(i % 2 == 0 ? "0x" : "-0x");
            for (int j = 0; j < count; j++) {
                if (j == dot) value.append('.');
                value.append(alphabet.charAt(random.nextInt(16)));
            }
            if (dot == count) value.append('.');
            value.append('p').append(random.nextInt(2401) - 1200);
            String text = value.toString();
            System.out.println("random_" + i + "=" + text + "," + Long.toHexString(Double.doubleToRawLongBits(Double.parseDouble(text))));
        }
    }
}
