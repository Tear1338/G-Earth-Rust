import gearth.protocol.HPacket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

// Same finite workloads as tools/benchmark.rs; startup and warm-up excluded.
public class JavaBenchmark {
    static final class Rc4 {
        private final int[] s = new int[256];
        private int i;
        private int j;

        Rc4(byte[] key) {
            for (int k = 0; k < 256; k++) {
                s[k] = k;
            }
            int jj = 0;
            for (int k = 0; k < 256; k++) {
                jj = (jj + s[k] + (key[k % key.length] & 0xff)) & 0xff;
                int tmp = s[k];
                s[k] = s[jj];
                s[jj] = tmp;
            }
        }

        void apply(byte[] data) {
            for (int k = 0; k < data.length; k++) {
                i = (i + 1) & 0xff;
                j = (j + s[i]) & 0xff;
                int tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
                data[k] ^= (byte) s[(s[i] + s[j]) & 0xff];
            }
        }
    }

    static long[] sampleConstruct(int iterations) {
        long start = System.nanoTime(), checksum = 0;
        for (int i = 0; i < iterations; i++) {
            HPacket p = new HPacket(123);
            p.appendInt(i);
            p.appendString("hello");
            p.appendBoolean(true);
            byte[] bytes = p.toBytes();
            checksum += (bytes[9] & 255) + bytes.length;
        }
        return new long[]{System.nanoTime() - start, checksum};
    }

    static long[] sampleRc4FrameRules(int iterations) {
        byte[] key = "gearth-benchmark-rc4-key-0123456".getBytes(StandardCharsets.US_ASCII);
        Rc4 encrypt = new Rc4(key);
        Rc4 decrypt = new Rc4(key);
        HPacket base = new HPacket(123);
        base.appendInt(42);
        base.appendString("room-chat-benchmark-payload");
        base.appendBoolean(true);
        byte[] template = base.toBytes();
        byte[] wire = new byte[template.length];
        HPacket replacement = new HPacket(124);

        long start = System.nanoTime(), checksum = 0;
        for (int i = 0; i < iterations; i++) {
            System.arraycopy(template, 0, wire, 0, template.length);
            encrypt.apply(wire);
            decrypt.apply(wire);
            int len = ((wire[0] & 0xff) << 24) | ((wire[1] & 0xff) << 16)
                    | ((wire[2] & 0xff) << 8) | (wire[3] & 0xff);
            if (len + 4 != wire.length) {
                throw new IllegalStateException("frame length mismatch");
            }
            HPacket packet = new HPacket(wire);
            int header = packet.headerId();
            if (header == 999) {
                continue;
            } else if (header == 124) {
                packet = replacement;
            }
            String expr = packet.toString();
            checksum += expr.length();
        }
        return new long[]{System.nanoTime() - start, checksum};
    }

    static byte[] readFrame(DataInputStream in) throws IOException {
        int len = in.readInt();
        byte[] frame = new byte[len + 4];
        frame[0] = (byte) (len >>> 24);
        frame[1] = (byte) (len >>> 16);
        frame[2] = (byte) (len >>> 8);
        frame[3] = (byte) len;
        in.readFully(frame, 4, len);
        return frame;
    }

    static long[] sampleLoopbackRelay(int iterations) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket remote = new ServerSocket(0, 16, loopback);
             ServerSocket relayListen = new ServerSocket(0, 16, loopback)) {
            int remotePort = remote.getLocalPort();
            int relayPort = relayListen.getLocalPort();
            long[] serverChecksum = new long[1];

            Thread serverThread = new Thread(() -> {
                try (Socket s = remote.accept();
                     DataInputStream in = new DataInputStream(s.getInputStream());
                     DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                    s.setTcpNoDelay(true);
                    long sum = 0;
                    for (int i = 0; i < iterations; i++) {
                        byte[] frame = readFrame(in);
                        int header = ((frame[4] & 0xff) << 8) | (frame[5] & 0xff);
                        sum += header + frame.length;
                        out.write(frame);
                        out.flush();
                    }
                    serverChecksum[0] = sum;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            serverThread.start();

            Thread relayThread = new Thread(() -> {
                try (Socket clientSide = relayListen.accept();
                     Socket serverSide = new Socket(loopback, remotePort)) {
                    clientSide.setTcpNoDelay(true);
                    serverSide.setTcpNoDelay(true);
                    Thread c2s = new Thread(() -> {
                        try (DataInputStream in = new DataInputStream(clientSide.getInputStream());
                             DataOutputStream out = new DataOutputStream(serverSide.getOutputStream())) {
                            for (int i = 0; i < iterations; i++) {
                                byte[] frame = readFrame(in);
                                int header = ((frame[4] & 0xff) << 8) | (frame[5] & 0xff);
                                if (header != 999) {
                                    out.write(frame);
                                    out.flush();
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    });
                    Thread s2c = new Thread(() -> {
                        try (DataInputStream in = new DataInputStream(serverSide.getInputStream());
                             DataOutputStream out = new DataOutputStream(clientSide.getOutputStream())) {
                            for (int i = 0; i < iterations; i++) {
                                byte[] frame = readFrame(in);
                                out.write(frame);
                                out.flush();
                            }
                        } catch (Exception ignored) {
                        }
                    });
                    c2s.start();
                    s2c.start();
                    c2s.join();
                    s2c.join();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            relayThread.start();

            HPacket packet = new HPacket(123);
            packet.appendInt(7);
            packet.appendString("loopback-e2e");
            byte[] payload = packet.toBytes();

            long elapsed;
            long clientChecksum = 0;
            try (Socket client = new Socket(loopback, relayPort);
                 DataOutputStream out = new DataOutputStream(client.getOutputStream());
                 DataInputStream in = new DataInputStream(client.getInputStream())) {
                client.setTcpNoDelay(true);
                long start = System.nanoTime();
                for (int i = 0; i < iterations; i++) {
                    out.write(payload);
                    out.flush();
                    byte[] echoed = readFrame(in);
                    int header = ((echoed[4] & 0xff) << 8) | (echoed[5] & 0xff);
                    clientChecksum += header + echoed.length;
                }
                elapsed = System.nanoTime() - start;
            }
            relayThread.join();
            serverThread.join();
            return new long[]{elapsed, clientChecksum + serverChecksum[0]};
        }
    }

    public static void main(String[] args) throws Exception {
        int iterations = 250_000;
        for (int i = 0; i < 5; i++) {
            sampleConstruct(iterations);
        }
        System.out.println("runtime,workload,iterations,nanoseconds,checksum");
        for (int i = 0; i < 5; i++) {
            long[] result = sampleConstruct(iterations);
            System.out.println("java,construct_packet," + iterations + "," + result[0] + "," + result[1]);
        }

        int pipelineIterations = 50_000;
        sampleRc4FrameRules(5_000);
        for (int i = 0; i < 5; i++) {
            long[] result = sampleRc4FrameRules(pipelineIterations);
            System.out.println("java,rc4_frame_rules," + pipelineIterations + "," + result[0] + "," + result[1]);
        }

        int relayIterations = 2_000;
        try {
            sampleLoopbackRelay(200);
            for (int i = 0; i < 3; i++) {
                long[] result = sampleLoopbackRelay(relayIterations);
                System.out.println("java,loopback_relay_e2e," + relayIterations + "," + result[0] + "," + result[1]);
            }
        } catch (IOException ignored) {
        }
    }
}
