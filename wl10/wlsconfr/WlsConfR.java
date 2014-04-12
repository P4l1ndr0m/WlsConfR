package wlsconfr;

import com.rsa.jsafe.JSAFE_IVException;
import com.rsa.jsafe.JSAFE_InvalidKeyException;
import com.rsa.jsafe.JSAFE_InvalidParameterException;
import com.rsa.jsafe.JSAFE_InvalidUseException;
import com.rsa.jsafe.JSAFE_UnimplementedException;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WlsConfR
{

    public WlsConfR()
    {
    }

    private static byte[] readBytes(InputStream inputstream)
        throws IOException
    {
        int i = inputstream.read();
        byte abyte0[] = new byte[i];
        inputstream.read(abyte0);
        return abyte0;
    }

    public static void main(String args[]) throws FileNotFoundException, IOException, JSAFE_UnimplementedException, JSAFE_InvalidParameterException, JSAFE_IVException, JSAFE_InvalidUseException, JSAFE_InvalidKeyException
    {
        FileInputStream fileinputstream = null;
        fileinputstream = new FileInputStream(new File("./SerializedSystemIni.dat"));
        byte salt[] = readBytes(fileinputstream);
        int i = fileinputstream.read();
        byte key[] = readBytes(fileinputstream);
        byte aeskey[] = readBytes(fileinputstream);
        String PW = "0xccb97558940b82637c8bec3c770f86fa3a391a56";
        char ac[] = new char[PW.length()];
        PW.getChars(0, PW.length(), ac, 0);
        JSafeEncryptionServiceImpl jsi = new JSafeEncryptionServiceImpl(aeskey, salt, PW);
        ClearOrEncryptedService cls = new ClearOrEncryptedService(jsi);
        String enc_value = args[0];
        System.out.println(cls.decrypt(enc_value));
        fileinputstream.close();
    }
} 