package pe.gob.mtc.walletprovider.sync;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Repository
public class DiagnosticsOutbox {
    private final JdbcTemplate jdbc;
    public DiagnosticsOutbox(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    public void enqueueRegister(String installationId,String keyId,String platform,String spki) {
        jdbc.update("INSERT INTO wallet_provider.wp_diagnostics_outbox "
                +"(installation_id,key_id,platform,public_key_spki_b64,action) VALUES(?,?,?,?,'REGISTER')",
                installationId,keyId,platform,spki);
    }
    public void enqueueRevoke(String installationId,String keyId,String platform) {
        jdbc.update("INSERT INTO wallet_provider.wp_diagnostics_outbox "
                +"(installation_id,key_id,platform,action) VALUES(?,?,?,'REVOKE')",
                installationId,keyId,platform);
    }

    public record Work(long id,String installationId,String keyId,String platform,String spki,String action,UUID leaseId,int attempts) {}

    @Transactional
    public List<Work> claim(int count) {
        UUID lease=UUID.randomUUID();
        return jdbc.query("WITH chosen AS (SELECT id FROM wallet_provider.wp_diagnostics_outbox "
                +"WHERE (state='PENDING' AND available_at<=CURRENT_TIMESTAMP) "
                +"OR (state='IN_FLIGHT' AND leased_until<CURRENT_TIMESTAMP) "
                +"ORDER BY id LIMIT ? FOR UPDATE SKIP LOCKED) "
                +"UPDATE wallet_provider.wp_diagnostics_outbox o "
                +"SET state='IN_FLIGHT',attempts=attempts+1,lease_id=?,leased_until=CURRENT_TIMESTAMP+INTERVAL '120 seconds' "
                +"FROM chosen WHERE o.id=chosen.id "
                +"RETURNING o.id,o.installation_id,o.key_id,o.platform,o.public_key_spki_b64,o.action,o.lease_id,o.attempts",
                (rs,row)->new Work(rs.getLong("id"),rs.getString("installation_id"),rs.getString("key_id"),
                        rs.getString("platform"),rs.getString("public_key_spki_b64"),rs.getString("action"),
                        rs.getObject("lease_id",UUID.class),rs.getInt("attempts")),count,lease);
    }
    @Transactional
    public void complete(Work work) {
        jdbc.update("UPDATE wallet_provider.wp_diagnostics_outbox SET state='DONE',finished_at=CURRENT_TIMESTAMP,"
                +"leased_until=NULL,lease_id=NULL,public_key_spki_b64=NULL "
                +"WHERE id=? AND lease_id=? AND state='IN_FLIGHT'",work.id(),work.leaseId());
    }
    @Transactional
    public void retry(Work work) {
        // bounded exponential backoff, revocation never silently abandoned
        long seconds=Math.min(900L,(1L<<Math.min(10,work.attempts()))*2L);
        jdbc.update("UPDATE wallet_provider.wp_diagnostics_outbox SET state='PENDING',"
                +"available_at=CURRENT_TIMESTAMP+(? * INTERVAL '1 second'),lease_id=NULL,leased_until=NULL "
                +"WHERE id=? AND lease_id=? AND state='IN_FLIGHT'",seconds,work.id(),work.leaseId());
    }
}
