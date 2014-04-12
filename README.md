## WlsConfR

Decrypt the entries in a weblogic server's config.xml using the SerializedSystemIni.dat file of the server.
The following application server are currently supported :

* **Weblogic 8,9**, data is encrypted using 3DES (EDE) with CBC and PKCS5Padding
* **Weblogic 10**, encryption algorithm is AES using CBC and PKCS5Padding

# Usage example

* make sure the SerializedSystem.ini, config.xml and the WlsConf\{8,10\}.jar are in the same folder as the main python script
* execute: ```python parse_and_decrypt.py```
* profit ! and continue pen-testing :)
