import gearth.app.protocol.crypto.BobbaCrypto;
import gearth.app.protocol.crypto.BobbaChaChaKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
public class BobbaOracle {
    static void emit(String name,byte[] bytes){System.out.println(name+"="+HexFormat.of().formatHex(bytes));}
    public static void main(String[] args){
        BobbaCrypto a=new BobbaCrypto(BigInteger.valueOf(12345)),b=new BobbaCrypto(BigInteger.valueOf(67890));
        emit("bobba_public_a",a.generatePublicKey().getBytes(StandardCharsets.US_ASCII));emit("bobba_public_b",b.generatePublicKey().getBytes(StandardCharsets.US_ASCII));a.setServerPublicKey(b.generatePublicKey());
        BobbaChaChaKey[] keys={a.getC2sData(),a.getC2sHeader(),a.getS2cData(),a.getS2cHeader()};
        for(int i=0;i<keys.length;i++){emit("bobba_key_"+i,keys[i].getKey());emit("bobba_nonce_"+i,keys[i].getNonce());}
        emit("bobba_cipher_0",BobbaCrypto.applyChaCha(new byte[]{1,2,3,4,5},0,5,a.getC2sData()));emit("bobba_cipher_1",BobbaCrypto.applyChaCha(new byte[]{1,2,3,4,5},0,5,a.getC2sData()));
        emit("bobba_header",BobbaCrypto.applyChaCha(new byte[]{1,64,64,100},0,4,a.getC2sHeader()));
    }
}
