package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class HolderIdentityImportCryptoTest {
    private HolderIdentityCrypto crypto() {
        byte[] a = new byte[32], b = new byte[32];
        new SecureRandom().nextBytes(a); new SecureRandom().nextBytes(b);
        return new HolderIdentityCrypto(Base64.getEncoder().encodeToString(a),
            Base64.getEncoder().encodeToString(b), 1);
    }
    @Test void encryptedRowsAreRandomizedAndAuthenticated() {
        var crypto = crypto();
        String raw = "01234567|AB123|Mesa 1|2027-11-24";
        byte[] first = crypto.encryptImportRow(raw), second = crypto.encryptImportRow(raw);
        assertFalse(Arrays.equals(first, second));
        assertEquals(raw, crypto.decryptImportRow(first));
        first[first.length - 1] ^= 1;
        assertThrows(SecurityException.class, () -> crypto.decryptImportRow(first));
    }
    @Test void importCipherCannotBeUsedAsDniCipher() {
        var crypto = crypto();
        byte[] wrapped = crypto.encryptImportRow("01234567|AB|A|2027-11-24");
        assertThrows(SecurityException.class, () -> crypto.decryptDni(wrapped));
    }
}
