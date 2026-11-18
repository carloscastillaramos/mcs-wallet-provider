package pe.gob.mtc.walletprovider.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pe.gob.mtc.walletprovider.domain.ChallengeRepository;

/** Limited asynchronous cleanup; never logs nonces or installation identifiers. */
@Component
public class ChallengeMaintenance {
    private static final Logger log = LoggerFactory.getLogger(ChallengeMaintenance.class);
    private final ChallengeRepository challenges;

    public ChallengeMaintenance(ChallengeRepository challenges) { this.challenges = challenges; }

    @Scheduled(fixedDelayString = "${CHALLENGE_CLEANUP_INTERVAL_MS:3600000}")
    public void clean() {
        try {
            int total = 0;
            for (int i = 0; i < 50; i++) {
                int count = challenges.purgeExpiredBatch();
                total += count;
                if (count < 1000) break;
            }
            if (total > 0) log.info("EXPIRED_CHALLENGES_PURGED count={}", total);
        } catch (RuntimeException unavailable) {
            log.warn("CHALLENGE_PURGE_UNAVAILABLE");
        }
    }
}
