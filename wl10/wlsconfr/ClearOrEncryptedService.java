package wlsconfr;

import java.io.IOException;
import sun.misc.BASE64Decoder;


public final class ClearOrEncryptedService
{

    public boolean isEncrypted(String s)
    {
        return s.startsWith(encryptedPrefix);
    }

    public ClearOrEncryptedService(JSafeEncryptionServiceImpl encryptionservice)
    {
        encryptedPrefix = null;
        encryptionService = null;
        encryptionService = encryptionservice;
        encryptedPrefix = (new StringBuilder()).append("{").append("AES").append("}").toString();
    }

    public String decrypt(String s)
        throws IOException
    {
        if(!isEncrypted(s))
        {
            return s;
        } else
        {
            String s1 = s.substring(encryptedPrefix.length());
            byte abyte0[] = (new BASE64Decoder()).decodeBuffer(s1);
            return encryptionService.decryptString(abyte0);
        }
    }

    private String encryptedPrefix;
    private JSafeEncryptionServiceImpl encryptionService;
}
