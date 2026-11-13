// Mirrors the exact time-window loop in pinned beta-29 Scheduler.java.
public final class JavaSchedulerCatchupOracle {
    public static void main(String[] args) {
        long[][] cases = {
            {10000, 1, 100, 0}, {10000, 101, 100, 0}, {10100, 251, 100, 25},
            {10499, 500, 500, 0}, {10500, 1001, 500, 500}, {10000, 301, 1, 0},
            {20001, 500, 250, 1}, {20000, 1, 250, 1}
        };
        for (long[] c : cases) {
            long t = c[0], changed = c[1], delay = c[2], offset = c[3];
            int count = 0;
            for (int i = 0; i < changed; i++) {
                if ((t - i) % delay == offset) count++;
            }
            System.out.println(t + "," + changed + "," + delay + "," + offset + "=" + count);
        }
    }
}
