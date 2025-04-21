package top.anyel.server.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/*
 * Author: Anyel EC
 * Github: https://github.com/Anyel-ec
 * Creation date: 20/04/2025
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {



    @Order(1) // Specifies the order of this security filter chain. It has a higher priority (lower number).
    @Bean // Marks this method as a Spring bean to be managed by the Spring container.
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer(); // Configures the OAuth2 Authorization Server.

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // Matches requests to the authorization server endpoints.
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated()) // Requires authentication for all requests.
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"), // Redirects to the login page for unauthenticated HTML requests.
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML) // Applies this behavior only for HTML requests.
                        )
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // Configures the resource server to use JWT for token validation.

        return http.build(); // Builds and returns the configured SecurityFilterChain.
    }


    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.disable())
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("iva")
                .password("{noop}123456")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Configuration for the OIDC (OpenID Connect) client
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString()) // Generates a unique ID for the client
                .clientId("oidc-client") // Client ID
                .clientSecret("{noop}123456789") // Client secret (not encoded, indicated by {noop})
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Client authentication method
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Grant type: Authorization Code
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Grant type: Refresh Token
                .redirectUri("https://oauthdebugger.com/debug") // Redirect URI for the client
                .scope(OidcScopes.OPENID) // Scope: OpenID
                .scope(OidcScopes.PROFILE) // Scope: Profile
                .scope("read") // Custom scope: Read
                .scope("write") // Custom scope: Write
                .build(); // Builds the registered client

        // Configuration for the OAuth2 client
        RegisteredClient oauthClient = RegisteredClient.withId(UUID.randomUUID().toString()) // Generates a unique ID for the client
                .clientId("oauth-client") // Client ID
                .clientSecret("{noop}12345678910") // Client secret (not encoded, indicated by {noop})
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Client authentication method
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Grant type: Authorization Code
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Grant type: Refresh Token
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oauth-client") // Redirect URI for the client
                .redirectUri("http://127.0.0.1:8080/authorized") // Additional redirect URI
                .postLogoutRedirectUri("http://127.0.0.1:8080/logout") // Post-logout redirect URI
                .scope(OidcScopes.OPENID) // Scope: OpenID
                .scope(OidcScopes.PROFILE) // Scope: Profile
                .scope("read") // Custom scope: Read
                .scope("write") // Custom scope: Write
                .build(); // Builds the registered client

        // Returns an in-memory repository containing the registered clients
        return new InMemoryRegisteredClientRepository(oidcClient, oauthClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}