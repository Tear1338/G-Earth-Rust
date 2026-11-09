import java.util.Random;
public class JavaDoubleFormatOracle {
 public static void main(String[] args) {
  long[] edge={1,2,3,0x0010000000000000L,0x7fefffffffffffffL,Double.doubleToRawLongBits(1e23),Double.doubleToRawLongBits(1e-4)};
  for(long bits:edge) System.out.printf("%016x=%s%n",bits,Double.toString(Double.longBitsToDouble(bits)));
  for(long bits=1;bits<=10000;bits++) System.out.printf("%016x=%s%n",bits,Double.toString(Double.longBitsToDouble(bits)));
  for(long bits=1;bits<=10000;bits++) {long signed=bits | Long.MIN_VALUE; System.out.printf("%016x=%s%n",signed,Double.toString(Double.longBitsToDouble(signed)));}
  for(int exponent=-323;exponent<=308;exponent++) {
   double power=Double.parseDouble("1e"+exponent);
   for(double value:new double[]{Math.nextDown(power),power,Math.nextUp(power),-power}) if(Double.isFinite(value)) System.out.printf("%016x=%s%n",Double.doubleToRawLongBits(value),Double.toString(value));
  }
  Random r=new Random(413); for(int i=0;i<5000;i++){long bits=r.nextLong();if(Double.isFinite(Double.longBitsToDouble(bits)))System.out.printf("%016x=%s%n",bits,Double.toString(Double.longBitsToDouble(bits)));}
 }
}
