package org.lucky0111.pettalk.util.auth;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getProvider(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("provider", String.class);
    }

    public String getSocialId(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("socialId", String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String provider, String socialId, String role, Long expiredMs) {
        System.out.println("JWT 토큰 생성 - 사용자: " + provider + " " + socialId + ", 역할: " + role);
        try {
            String token = Jwts.builder()
                    .claim("provider", provider)
                    .claim("socialId", socialId)
                    .claim("role", role)
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis() + expiredMs))
                    .signWith(secretKey)
                    .compact();
            System.out.println("JWT 토큰 생성 성공: " + token.substring(0, Math.min(token.length(), 10)) + "...");
            return token;
        } catch (Exception e) {
            System.out.println("JWT 토큰 생성 중 오류 발생: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
