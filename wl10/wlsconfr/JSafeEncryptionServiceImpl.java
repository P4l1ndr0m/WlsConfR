package wlsconfr;

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


            int ii = 16; //keycontext.randomLen;

            int jj = abyte0.length - ii;
            if(jj < 0)
                throw new IllegalStateException("Invalid input length");
            byte abyte1[] = new byte[jj];
            if(ii > 0)
            {
                jsafe_symmetriccipher.setIV(abyte0, 0, ii);
                jsafe_symmetriccipher.decryptReInit();
            }
            int k = jsafe_symmetriccipher.decryptUpdate(abyte0, ii, jj, abyte1, 0);
            int l = jsafe_symmetriccipher.decryptFinal(abyte1, k);
            int i1 = k + l;
            if(i1 < abyte1.length)
            {
                byte abyte2[] = new byte[i1];
                System.arraycopy(abyte1, 0, abyte2, 0, i1);
                abyte1 = abyte2;
            }

            abyte3 = abyte1;

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
        log("Initializing decrypt cipher");
        decryptCipher = JSAFE_SymmetricCipher.getInstance("AES/CBC/PKCS5Padding", "Java");
//        decryptCipher.setIV(abyte3, 0, abyte3.length);
        decryptCipher.decryptInit(jsafe_secretkey);
        log("all good!");


        j = 0;

        for (int i = 0; i < ac.length; i++) {
            ac[i] = '\0';
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
//        System.out.println("logging:" + s1);
    }


    static final int RANDOM_DATA_LENGTH = 24;
    static final String ENCODING = "UTF-8";
    private static final boolean DEBUG = false;
    private JSAFE_SymmetricCipher encryptCipher;
    private JSAFE_SymmetricCipher decryptCipher;
}
