package com.simpleauthserver.pkcedemo.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    @Value("${PRIVATE_KEY_BASE64}")
    private String PRIVATE_KEY_BASE64;

    @Value("${PUBLIC_KEY_BASE64}")
    private String PUBLIC_KEY_BASE64;

    @Bean
    public JwtEncoder jwtEncoder() throws NoSuchAlgorithmException {
        return new NimbusJwtEncoder(jwkSource());
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAPrivateKey privateKey = getPrivateKey();
        RSAPublicKey publicKey = getPublicKey();
        String kid = generateKeyId(publicKey);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(kid)  // Set your desired kid
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        RSAPublicKey publicKey = getPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    private RSAPrivateKey getPrivateKey() {
        String privateKeyString = PRIVATE_KEY_BASE64;
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key", e);
        }
    }

    private RSAPublicKey getPublicKey() {
        String publicKeyString = PUBLIC_KEY_BASE64;
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load public key", e);
        }
    }

    public String generateKeyId(RSAPublicKey publicKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedKey = publicKey.getEncoded();
        byte[] hash = digest.digest(encodedKey);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

}