import gearth.extensions.parsers.HEntityUpdate;
import gearth.extensions.parsers.HPoint;
import gearth.protocol.HPacket;
import java.util.Locale;

public class JavaEntityUpdateOracle {
    public static void main(String[] args) {
        String[] cases = {"sit ", "lay  ", "flatctrl ", "mv 1,2,", "mv 0x-1,2,3", "sign -+1", "mv +0x1,-02,3", "sit  /sign 1", "mv 1,2,3,", "sign 0x1", "mv --1,2,3", "sit 1/lay 2/sign 18/mv 1,2,3/flatctrl 1", "flatctrl 1/mv 1,2,3/sit 1/sign 11/lay 1", "mv 1,2,3/mv 4,5,6", "sign 1/sign 2", "sit 1/unknown 4/lay 1", "sign 19", "sign -1", "sign +1", "mv 1,,3", "mv 1,2,three", "mv 1,2", "mv 1,2,3,4", "/sit 1//lay 1/", "sit\t1", " flatctrl 1", "flatctrl 1/flatctrl 1"};
        for (int i = 0; i < cases.length; i++) {
            HPacket packet = new HPacket(1);
            packet.appendInt(1).appendInt(7).appendInt(2).appendInt(3).appendString("1.0")
                .appendInt(0).appendInt(1).appendString(cases[i]);
            try {
                HEntityUpdate update = HEntityUpdate.parse(packet)[0];
                HPoint moving = update.getMovingTo();
                String coordinates = moving == null ? "none" : String.format(Locale.ROOT, "%d,%d,%.1f", moving.getX(), moving.getY(), moving.getZ());
                System.out.println("case_" + i + "=" + update.getAction() + ";" + update.getStance() + ";" + update.getSign() + ";" + update.isController() + ";" + coordinates + ";" + packet.getReadIndex());
            } catch (RuntimeException e) {
                System.out.println("case_" + i + "=error;" + packet.getReadIndex());
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
