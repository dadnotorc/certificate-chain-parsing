import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Given
 * 1. Use an open-source tool, generate two X.509 certificates. The second certificate should be signed by the first,
 *    forming a certificate chain in PKCS12 (.p12) format.
 * 2. Write code with the help of an open-source library,
 *    that will print out whether a certificate is a self-signed certificate, and the fingerprint of each certificate.
 *
 * TODO:
 * 1. Handle garbage p12 files gracefully
 * 2. Distinguish between a bad cert (i.e. tamper with cacert.pem so that verification fails) and cert that is not self-signed.
 *
 * A tampered cert is technically not self-signed, but a better solution would treat a bad cert as an error condition.
 * This would have required a design change, where a cert chain would need to be provided as input.
 */
public class Certificate_chain_parsing {
    public static void main(String[] args) throws Exception {

        File[] files = getSelectedFiles();
        System.out.println(files.length + " certificate files are selected");

        for (File file : files) {
            System.out.println("\nExamining " + file.getPath());
            KeyStore p12 = null;
            p12 = KeyStore.getInstance("pkcs12");
            p12.load(new FileInputStream(file), "password".toCharArray());
            Enumeration<String> e = p12.aliases();
            while (e.hasMoreElements()) {
                String alias = e.nextElement();
                X509Certificate cert = (X509Certificate) p12.getCertificate(alias);
                System.out.println("Certificate fingerprint (SHA-256): " + getSHA256Fingerprint(cert));

                cert.checkValidity();

                try {
                    cert.verify(cert.getPublicKey());
                    System.out.println("Certificate " + file.getName() + " is self signed");
                } catch (SignatureException signatureException) {
                    System.out.println("Certificate " + file.getName() + " is NOT self signed");
                }
            }
        }
        System.exit(0);
    }

    // Use UI to select one or more PKCS#12 certificate file(s)

    private static File[] getSelectedFiles() {
        FileDialog dialog = new FileDialog((Frame) null, "Select PKCS#12 certificate file(s) to open", FileDialog.LOAD);
        dialog.setFilenameFilter(new FilenameFilter() {
            @Override
            public boolean accept(File file, String s) {
                return s.toLowerCase().endsWith(".p12");
            }
        });
        dialog.setMultipleMode(true);
        dialog.setVisible(true);

        return dialog.getFiles();
    }

    // Get the SHA-256 fingerprint of an X509 certificate
    private static String getSHA256Fingerprint(X509Certificate cert) throws Exception {
        byte[] derEncodedCert = cert.getEncoded();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        return String.format("%040x", new BigInteger(1, sha256.digest(derEncodedCert)));
    }
}
