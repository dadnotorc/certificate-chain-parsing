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
