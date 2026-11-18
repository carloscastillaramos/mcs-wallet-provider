package pe.gob.mtc.walletprovider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
public class WalletProviderApplication {
    public static void main(String[] args) { SpringApplication.run(WalletProviderApplication.class, args); }
}
