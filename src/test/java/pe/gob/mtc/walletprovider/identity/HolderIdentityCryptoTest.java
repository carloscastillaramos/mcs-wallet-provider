package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class HolderIdentityCryptoTest {
    private HolderIdentityCrypto crypto() {
        byte[] hmac = new byte[32];
        byte[] aes = new byte[32];
        Arrays.fill(hmac, (byte) 0x11);
        Arrays.fill(aes, (byte) 0x22);
        return new HolderIdentityCrypto(Base64.getEncoder().encodeToString(hmac),
            Base64.getEncoder().encodeToString(aes), 1);
    }

    @Test void dniHmacDeterministicAndNotPlaintext() {
        HolderIdentityCrypto c = crypto();
        byte[] a = c.indexDni("01234567");
        assertArrayEquals(a, c.indexDni("01234567"));
        assertEquals(32, a.length);
        assertFalse(Arrays.equals(a, "01234567".getBytes()));
        assertFalse(Arrays.equals(a, c.indexDni("01234568")));
    }

    @Test void encryptionIsRandomizedAndAuthenticated() {
        HolderIdentityCrypto c = crypto();
        byte[] first = c.encryptDni("01234567");
        byte[] second = c.encryptDni("01234567");
        assertFalse(Arrays.equals(first, second));
        assertEquals("01234567", c.decryptDni(first));
        assertEquals("01234567", c.decryptDni(second));
        first[first.length - 1] ^= 1;
        assertThrows(SecurityException.class, () -> c.decryptDni(first));
    }

    @Test void rejectsInvalidDocumentAndMalformedCiphertext() {
        HolderIdentityCrypto c = crypto();
        for (String dni : new String[] {"1234567", "123456789", "1234ABCD", "١٢٣٤٥٦٧٨"}) {
            assertThrows(IllegalArgumentException.class, () -> c.indexDni(dni));
            assertThrows(IllegalArgumentException.class, () -> c.encryptDni(dni));
        }
        assertThrows(SecurityException.class, () -> c.decryptDni(new byte[8]));
    }

    @Test void failsClosedOnMissingOrEqualKeys() {
        String k = Base64.getEncoder().encodeToString(new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> new HolderIdentityCrypto("", k, 1));
        assertThrows(IllegalArgumentException.class, () -> new HolderIdentityCrypto(k, k, 1));
        assertThrows(IllegalArgumentException.class, () -> new HolderIdentityCrypto("invalid!", k, 1));
        assertThrows(IllegalArgumentException.class, () -> new HolderIdentityCrypto(k, "bad", 1));
    }

    @Test void keyRotationWithoutMigrationChangesLookupIndex() {
        HolderIdentityCrypto c = crypto();
        byte[] different = new byte[32];
        Arrays.fill(different, (byte) 0x44);
        byte[] encryption = new byte[32];
        Arrays.fill(encryption, (byte) 0x22);
        HolderIdentityCrypto rotated = new HolderIdentityCrypto(
            Base64.getEncoder().encodeToString(different),
            Base64.getEncoder().encodeToString(encryption), 2);
        assertFalse(Arrays.equals(c.indexDni("01234567"), rotated.indexDni("01234567")));
    }
}
