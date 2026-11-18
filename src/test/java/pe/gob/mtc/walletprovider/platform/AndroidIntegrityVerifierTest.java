package pe.gob.mtc.walletprovider.platform;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AndroidIntegrityVerifierTest {
    @Test void requestHashIsBoundToEveryField() {
        String first=AndroidIntegrityVerifier.requestHash("id","nonce","key","pem");
        assertEquals(first,AndroidIntegrityVerifier.requestHash("id","nonce","key","pem"));
        assertNotEquals(first,AndroidIntegrityVerifier.requestHash("id","other","key","pem"));
        assertNotEquals(first,AndroidIntegrityVerifier.requestHash("id","nonce","other","pem"));
        assertNotEquals(first,AndroidIntegrityVerifier.requestHash("id","nonce","key","different"));
    }
}
