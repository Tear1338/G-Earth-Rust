import gearth.protocol.HPacket;
// Same finite workload as tools/benchmark.rs; startup and warm-up excluded.
public class JavaBenchmark {
    static long[] sample(int iterations){
        long start=System.nanoTime(),checksum=0;
        for(int i=0;i<iterations;i++){
            HPacket p=new HPacket(123);p.appendInt(i);p.appendString("hello");p.appendBoolean(true);
            byte[] bytes=p.toBytes();checksum+=(bytes[9]&255)+bytes.length;
        }
        return new long[]{System.nanoTime()-start,checksum};
    }
    public static void main(String[] args){
        int iterations=250_000;
        for(int i=0;i<5;i++)sample(iterations);
        System.out.println("runtime,workload,iterations,nanoseconds,checksum");
        for(int i=0;i<5;i++){long[] result=sample(iterations);System.out.println("java,construct_packet,"+iterations+","+result[0]+","+result[1]);}
    }
}
