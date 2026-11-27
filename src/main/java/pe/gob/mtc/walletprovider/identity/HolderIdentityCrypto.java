package pe.gob.mtc.walletprovider.identity;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Proteccion de DNI acreditados: indice HMAC y cifrado aleatorio AES-256-GCM.
 * Las claves son independientes y NO se guardan en la base de datos.
 * No agregar toString/logs con DNI, ciphertext ni claves.
 */
public final class HolderIdentityCrypto {
    private static final byte[] AAD = "mtc:wallet-provider:holder:DNI:v1".getBytes(StandardCharsets.US_ASCII);
    private final byte[] hmacKey;
    private final byte[] encryptionKey;
    private final int keyVersion;
    private final SecureRandom random = new SecureRandom();

    public HolderIdentityCrypto(String hmacKeyBase64, String encryptionKeyBase64, int keyVersion) {
        this.hmacKey = decodeKey(hmacKeyBase64, "HMAC");
        this.encryptionKey = decodeKey(encryptionKeyBase64, "encryption");
        if (MessageDigest.isEqual(hmacKey, encryptionKey))
            throw new IllegalArgumentException("Identity HMAC and encryption keys must differ");
        if (keyVersion < 1 || keyVersion > Short.MAX_VALUE)
            throw new IllegalArgumentException("Identity key version invalid");
        this.keyVersion = keyVersion;
    }

    private static byte[] decodeKey(String input, String label) {
        if (input == null || input.isBlank())
            throw new IllegalArgumentException("Identity " + label + " key missing");
        final byte[] decoded;
        try { decoded = Base64.getDecoder().decode(input); }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Identity " + label + " key invalid", e);
        }
        if (decoded.length != 32)
            throw new IllegalArgumentException("Identity " + label + " key must be 256-bit");
        return decoded;
    }

    public int keyVersion() { return keyVersion; }

    public byte[] indexDni(String dni) {
        validateDni(dni);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return mac.doFinal(("DNI:" + dni).getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Identity index unavailable", e);
        }
    }

    public byte[] encryptDni(String dni) {
        validateDni(dni);
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                new GCMParameterSpec(128, iv));
            cipher.updateAAD(AAD);
            byte[] encrypted = cipher.doFinal(dni.getBytes(StandardCharsets.US_ASCII));
            byte[] blob = Arrays.copyOf(iv, iv.length + encrypted.length);
            System.arraycopy(encrypted, 0, blob, iv.length, encrypted.length);
            return blob;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Identity encryption unavailable", e);
        }
    }

    private static final byte[] IMPORT_AAD =
        "mtc:wallet-provider:institutional:import-row:v1".getBytes(StandardCharsets.US_ASCII);

    /** Envoltorio GCM de una fila validada; no se usa para otros tipos de datos. */
    public byte[] encryptImportRow(String validatedRecord) {
        if (validatedRecord == null || validatedRecord.isBlank() || validatedRecord.length() > 512)
            throw new IllegalArgumentException("Invalid institutional import row");
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                new GCMParameterSpec(128, iv));
            cipher.updateAAD(IMPORT_AAD);
            byte[] encrypted = cipher.doFinal(validatedRecord.getBytes(StandardCharsets.UTF_8));
            byte[] blob = Arrays.copyOf(iv, iv.length + encrypted.length);
            System.arraycopy(encrypted, 0, blob, iv.length, encrypted.length);
            return blob;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Institutional import encryption unavailable", e);
        }
    }

    /** Unicamente la aplicación transaccional de lotes accede al texto descifrado. */
    public String decryptImportRow(byte[] blob) {
        if (blob == null || blob.length < 29 || blob.length > 1024)
            throw new SecurityException("Institutional import row invalid");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(blob, 0, 12)));
            cipher.updateAAD(IMPORT_AAD);
            return new String(cipher.doFinal(blob, 12, blob.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ex) {
            throw new SecurityException("Institutional import authentication failed", ex);
        }
    }

    /** Solo para operaciones privilegiadas futuras; nunca entregar el DNI a clientes moviles. */
    String decryptDni(byte[] blob) {
        if (blob == null || blob.length < 12 + 16 + 8)
            throw new SecurityException("Identity ciphertext invalid");
        try {
            byte[] iv = Arrays.copyOfRange(blob, 0, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                new GCMParameterSpec(128, iv));
            cipher.updateAAD(AAD);
            String dni = new String(cipher.doFinal(blob, 12, blob.length - 12), StandardCharsets.US_ASCII);
            validateDni(dni);
            return dni;
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Identity ciphertext authentication failed", e);
        }
    }

    public static void validateDni(String dni) {
        if (dni == null || !dni.matches("[0-9]{8}"))
            throw new IllegalArgumentException("Accredited document invalid");
    }
}
