import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Independent JCE reference for beta-29 hotel wire algorithms; no network access. */
public final class JavaNitroCryptoOracle {
    static void emit(String name, byte[] data) {System.out.println(name+"="+HexFormat.of().formatHex(data));}
    public static void main(String[] args) throws Exception {
        byte[] key=new byte[16];for(int i=0;i<key.length;i++)key[i]=(byte)i;
        byte[] sso="fixture-sso".getBytes(StandardCharsets.UTF_8);
        byte[] hello=ByteBuffer.allocate(8+sso.length).putInt(4+sso.length).putShort((short)2419).putShort((short)sso.length).put(sso).array();
        for(int length:new int[]{12,16}) {byte[] iv=new byte[length];for(int i=0;i<length;i++)iv[i]=(byte)i;Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));emit("gcm"+length,cipher.doFinal(hello));}
        byte[] tripleKey=new byte[24];java.util.Arrays.fill(tripleKey,(byte)43);byte[] iv=new byte[8];java.util.Arrays.fill(iv,(byte)9);Cipher triple=Cipher.getInstance("DESede/CBC/PKCS5Padding");triple.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(tripleKey,"DESede"),new IvParameterSpec(iv));emit("des",ByteBuffer.allocate(16).put(iv).put(triple.doFinal(new byte[]{0,0,0,2,0,77})).array());
        MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update((byte)0x11);hash.update(sso);byte[] ctrKey=hash.digest(new byte[]{0x22});hash.reset();hash.update(sso);byte[] ctrIv=hash.digest(new byte[]{0x33});Cipher ctr=Cipher.getInstance("AES/CTR/NoPadding");ctr.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(ctrKey,0,16,"AES"),new IvParameterSpec(ctrIv,0,16));emit("ctr77",ctr.update(new byte[]{0,0,0,2,0,77}));emit("ctr78",ctr.update(new byte[]{0,0,0,2,0,78}));
    }
}
