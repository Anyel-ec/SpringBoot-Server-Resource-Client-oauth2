package top.anyel.resource.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
/*
 * Author: Anyel EC
 * Github: https://github.com/Anyel-ec
 * Creation date: 20/04/2025
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/resources/**").hasAnyAuthority("SCOPE_read", "SCOPE_write", "SCOPE_profile")

                        .requestMatchers(HttpMethod.POST, "/resources/**").hasAuthority("SCOPE_write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}