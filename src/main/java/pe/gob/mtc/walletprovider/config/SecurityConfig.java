package pe.gob.mtc.walletprovider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http.csrf(csrf->csrf.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a->a
                .requestMatchers("/actuator/health/**","/v3/api-docs/**","/swagger-ui/**","/swagger-ui.html","/api/v1/.well-known/jwks.json").permitAll()
                .requestMatchers(HttpMethod.POST,"/api/v1/enrollments/challenge","/api/v1/enrollments/android","/api/v1/enrollments/ios").permitAll()
                // This public binding route requires two independent cryptographic proofs and a one-time challenge.
                .requestMatchers(HttpMethod.POST,"/api/v1/installations/*/diagnostics-keys").permitAll()
                .requestMatchers(HttpMethod.GET,"/api/v1/installations/*/trust").hasAuthority("SCOPE_wallet.trust.read")
                .requestMatchers(HttpMethod.POST,"/api/v1/installations/*/revoke").hasAuthority("SCOPE_wallet.admin")
                .requestMatchers(HttpMethod.POST,"/api/v1/attestations/wallet/android","/api/v1/attestations/wallet/ios",
                    "/api/v1/attestations/keys/android","/api/v1/attestations/keys/ios",
                    "/api/v1/attestations/credential-keys/android").permitAll()
                .anyRequest().denyAll())
            .oauth2ResourceServer(o->o.jwt(Customizer.withDefaults())).build();
    }
}
