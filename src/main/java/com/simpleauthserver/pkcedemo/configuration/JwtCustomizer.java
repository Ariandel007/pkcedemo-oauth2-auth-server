package com.simpleauthserver.pkcedemo.configuration;

import com.simpleauthserver.pkcedemo.service.CustomUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class JwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        // Extract roles from authentication (CustomUserDetailsService)
        var authentication = context.getPrincipal();
        if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            var roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            context.getClaims()
                    .claim("roles", roles)
                    .claim("user_id", userDetails.getId()); // Extrae el ID directamente
        }

    }
}

//http://localhost:8080/oauth2/jwks


//http://localhost:8080/.well-known/openid-configuration
//This is the standard URL for OpenID Connect discovery, and it contains all the necessary endpoints, including the URL to retrieve the JWK Set (/oauth2/jwks).


//Resource Server necesary:

//@Configuration
//@EnableWebSecurity
//public class ResourceServerConfig {
//
//    @Value("${auth.server.issuer-uri}") // Set this to the Authorization Server's issuer URI
//    private String issuerUri;
//
//    @Bean
//    public JwtDecoder jwtDecoder() {
//        // Automatically discovers the JWK URI from the issuer's well-known metadata
//        return JwtDecoders.fromIssuerLocation(issuerUri);
//    }
//
//    @Bean
//    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .anyRequest().authenticated()
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt.decoder(jwtDecoder())) // Configure JWT decoder
//                );
//        return http.build();
//    }
//}
//
//@Bean
//SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//    http
//            .cors().and()
//            .authorizeHttpRequests((authorize) -> authorize
//                    .requestMatchers("/public/**").permitAll()
//                    .requestMatchers("/admin/**").hasAuthority("SCOPE_admin")
//                    .anyRequest().authenticated()
//            )
//            .oauth2ResourceServer(oauth2 -> oauth2
//                    .jwt(jwt -> jwt.decoder(jwtDecoder()))
//            )
//            .exceptionHandling((exceptions) -> exceptions
//                    .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
//                    .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
//            );
//    return http.build();
//}
//@Bean
//public CorsConfigurationSource corsConfigurationSource() {
//    CorsConfiguration configuration = new CorsConfiguration();
//    configuration.addAllowedOrigin("http://localhost:4200");
//    configuration.addAllowedMethod("*");
//    configuration.addAllowedHeader("*");
//    configuration.setAllowCredentials(true);
//    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//    source.registerCorsConfiguration("/**", configuration);
//    return source;
//}