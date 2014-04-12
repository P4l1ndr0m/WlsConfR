package wlsconfr;

import com.rsa.jsafe.*;

final class JSafeSecretKeyEncryptor
{

    JSafeSecretKeyEncryptor()
    {
    }

    static JSAFE_SecretKey decryptSecretKey(byte abyte0[], char ac[], byte abyte1[])
    {
        byte abyte2[] = doubleSalt(abyte1);
        byte abyte3[] = new byte[abyte0.length];
        log((new StringBuilder()).append("key material length: ").append(abyte3.length).toString());
        JSAFE_SecretKey jsafe_secretkey = null;
        JSAFE_SymmetricCipher jsafe_symmetriccipher = null;
        JSAFE_SecretKey jsafe_secretkey1 = null;
        JSAFE_SecureRandom jsafe_securerandom = null;
        try
        {
            jsafe_symmetriccipher = JSAFE_SymmetricCipher.getInstance("PBE/SHA1/RC2/CBC/PKCS12PBE-5-128", "Java");
            jsafe_symmetriccipher.setSalt(abyte1, 0, abyte1.length);
            jsafe_secretkey = jsafe_symmetriccipher.getBlankKey();
            jsafe_secretkey.setPassword(ac, 0, ac.length);
            jsafe_symmetriccipher.decryptInit(jsafe_secretkey);
            int i = jsafe_symmetriccipher.decryptUpdate(abyte0, 0, abyte0.length, abyte3, 0);
            int k = jsafe_symmetriccipher.decryptFinal(abyte3, i);
            int l = i + k;
            log((new StringBuilder()).append(l).append(" bytes of the array filled").toString());
            byte abyte4[] = new byte[l];
            System.arraycopy(abyte3, 0, abyte4, 0, abyte4.length);
            log("Initializing PRNG");
            jsafe_securerandom = (JSAFE_SecureRandom)JSAFE_SecureRandom.getInstance("MD5Random", "Java");
            log("getting cipher to generate key");
            jsafe_symmetriccipher = JSAFE_SymmetricCipher.getInstance("3DES_EDE/CBC/PKCS5Padding", "Java");
            log("blank key from cipher");
            jsafe_secretkey1 = jsafe_symmetriccipher.getBlankKey();
            log((new StringBuilder()).append("setting key data: ").append(abyte4.length).toString());
            jsafe_secretkey1.setSecretKeyData(abyte4, 0, abyte4.length);
        }
        catch(Exception exception) { }
        return jsafe_secretkey1;
    }

    static byte[] doubleSalt(byte abyte0[])
    {
        if(abyte0.length == 8)
        {
            return abyte0;
        } else
        {
            byte abyte1[] = new byte[8];
            System.arraycopy(abyte0, 0, abyte1, 0, 4);
            System.arraycopy(abyte0, 0, abyte1, 4, 4);
            return abyte1;
        }
    }

    public static void log(String s1)
    {
    }

    private static final String KEY_ALGORITHM = "PBE/SHA1/RC2/CBC/PKCS12PBE-5-128";
    private static final int SALT_LENGTH = 8;
    private static final boolean DEBUG = false;
} 