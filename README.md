# Certificate chain parsing

## Objective
1. Use an open-source tool, generate two X.509 certificates. The second certificate should be signed by the first,
forming a certificate chain in PKCS12 (.p12) format.
2. Write code with the help of an open-source library, 
that will print out whether a certificate is a self-signed certificate, and the fingerprint of each certificate. 

## Solutions
The following describes:
1. Generate test certificates
2. Run Java program to examine the certificates

### Prerequisites:
1. OpenSSL has been installed
2. Java environment has been configured

### Generate certificates
1. Generate a private key with 2048-bit RSA, and a self-signed certificate (CA). 
For the simplicity, "-nodes" is provided so that the private key won't be encrypted.
    ```
    openssl req -x509 -nodes -newkey rsa:2048 -keyout cakey.pem -out cacert.pem -subj "/C=CA/ST=ON/O=Some Company/OU=IT Department/CN=example.com"
    ```

2. Generate private key for a new sub CA, and a new CSR from the sub CA private key
    ```
    openssl req -nodes -newkey rsa:2048 -keyout clientkey.pem -out clientreq.csr -subj "/C=CA/ST=ON/O=Some Company/OU=R&D/CN=example.com"
    ```

3. Sign sub CA certificate using the CA certificate and its private key created earlier
    ```
    openssl x509 -req -in clientreq.csr -CA cacert.pem -CAkey cakey.pem -set_serial 01 -out clientcert.pem
    ```

4. Convert PEM certificate files to PKCS#12 format
    ```
    openssl pkcs12 -export -out ca.p12 -inkey cakey.pem -in cacert.pem

    openssl pkcs12 -export -out client.p12 -inkey clientkey.pem -in clientcert.pem -certfile cacert.pem
    ```

5. Use openssl and keytool to verify the content of the PKCS#12 file
    ```
    openssl pkcs12 -info -in client.p12

    keytool -list -keystore client.p12 -storetype PKCS12 -storepass password
    ```
   
6. Use keytool to create a keystore.jks repository and import the client.p12
    ```
    keytool -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS
    ```
   
   Note that the JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 
   which is an industry standard format using
    ```
    keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.jks -deststoretype pkcs12
    ```

### Run Java program
1. Compile and run Cert_chain_parsing.java file
    ```
    javac Cert_chain_parsing.java
    java Cert_chain_parsing
    ```