package wlsconfr;

import com.rsa.jsafe.*;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.rsa.jsafe.*;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class JSafeEncryptionServiceImpl
{

    public byte[] decryptBytes(byte abyte0[])
    {
        try {
            byte[] abyte3;
            JSAFE_SymmetricCipher jsafe_symmetriccipher = getDecryptCipher();
            byte[] abyte1 = new byte[abyte0.length];
            int i = jsafe_symmetriccipher.decryptUpdate(abyte0, 0, abyte0.length, abyte1, 0);
            int j = jsafe_symmetriccipher.decryptFinal(abyte1, i);
            int k = i + j;
            byte[] abyte2 = new byte[k];
            System.arraycopy(abyte1, 0, abyte2, 0, k);
            abyte1 = abyte2;
            abyte3 = abyte1;
            jsafe_symmetriccipher.clearSensitiveData();
            return abyte3;
        } catch (JSAFE_InputException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (JSAFE_PaddingException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (JSAFE_InvalidUseException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (JSAFE_IVException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String decryptString(byte abyte0[])
    {
        try {
            return new String(decryptBytes(abyte0), "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "###ERROR###";
    }

    public String getAlgorithm()
    {
        return "3DES";
    }

    JSafeEncryptionServiceImpl(byte abyte0[], byte abyte1[], String s) throws JSAFE_UnimplementedException, JSAFE_InvalidParameterException, JSAFE_IVException, JSAFE_InvalidUseException, JSAFE_InvalidKeyException
    {
        super();
        JSAFE_SecretKey jsafe_secretkey;
        char ac[];
        int j;


        jsafe_secretkey = null;
        ac = new char[s.length()];
        s.getChars(0, s.length(), ac, 0);

        log("Encryption service constructor called");
        log("Initializing secret key");
        jsafe_secretkey = JSafeSecretKeyEncryptor.decryptSecretKey(abyte0, ac, abyte1);
        log((new StringBuilder()).append("key: ").append(jsafe_secretkey.toString()).toString());
        log("Initializing encrypt cipher");
        encryptCipher = JSAFE_SymmetricCipher.getInstance("3DES_EDE/CBC/PKCS5Padding", "Java");
        byte abyte2[] = JSafeSecretKeyEncryptor.doubleSalt(abyte1);
        encryptCipher.setIV(abyte2, 0, abyte2.length);
        byte abyte3[] = encryptCipher.getIV();
        log((new StringBuilder()).append("IV Length: ").append(abyte3.length).toString());
        encryptCipher.encryptInit(jsafe_secretkey);
        log("Initializing decrypt cipher");
        decryptCipher = JSAFE_SymmetricCipher.getInstance("3DES_EDE/CBC/PKCS5Padding", "Java");
        decryptCipher.setIV(abyte3, 0, abyte3.length);
        decryptCipher.decryptInit(jsafe_secretkey);
        log("all good!");


        j = 0;

        for (int i = 0; i < ac.length; i++) {
            ac[i] = '\0';
        }

        if (jsafe_secretkey != null) {
            jsafe_secretkey.clearSensitiveData();
        }
        for (; j < ac.length; j++) {
            ac[j] = '\0';
        }

        if (jsafe_secretkey != null) {
            jsafe_secretkey.clearSensitiveData();
        }
    }

    private synchronized JSAFE_SymmetricCipher getDecryptCipher()
    {
        JSAFE_SymmetricCipher jsafe_symmetriccipher;
        jsafe_symmetriccipher = null;
        try {
            jsafe_symmetriccipher = (JSAFE_SymmetricCipher) decryptCipher.clone();
            return jsafe_symmetriccipher;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(JSafeEncryptionServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static void log(String s1)
    {
    }

    static final String OVERALL_ALGORITHM = "3DES";
    static final String ALGORITHM = "3DES_EDE/CBC/PKCS5Padding";
    static final int RANDOM_DATA_LENGTH = 24;
    static final String ENCODING = "UTF-8";
    private static final boolean DEBUG = false;
    private JSAFE_SymmetricCipher encryptCipher;
    private JSAFE_SymmetricCipher decryptCipher;
} 