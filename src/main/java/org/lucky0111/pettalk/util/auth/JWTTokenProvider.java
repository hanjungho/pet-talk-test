package org.lucky0111.pettalk.util.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * JWT 토큰 생성 및 검증을 담당하는 클래스
 */
@Slf4j
@Component
public class JWTTokenProvider {

    private final SecretKey secretKey;

    public JWTTokenProvider(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * 기본 JWT 토큰을 생성합니다.
     */
    public String createJwt(String provider, String socialId, UUID userId, String role, Long expiredMs) {
        log.debug("JWT 토큰 생성 - 사용자: {} {}, 역할: {}", provider, socialId, role);
        return buildToken(builder ->
                        builder.claim("provider", provider)
                                .claim("socialId", socialId)
                                .claim("userId", userId.toString())
                                .claim("role", role),
                expiredMs
        );
    }

    /**
     * 이메일 정보를 포함한 JWT 토큰을 생성합니다.
     */
    public String createJwtWithEmail(String provider, String socialId, UUID userId, String role, String email, Long expiredMs) {
        log.debug("JWT 토큰 생성 - 사용자: {} {}, 역할: {}, 이메일: {}", provider, socialId, role, email);
        return buildToken(builder ->
                        builder.claim("provider", provider)
                                .claim("socialId", socialId)
                                .claim("userId", userId.toString())
                                .claim("role", role)
                                .claim("email", email),
                expiredMs
        );
    }

    /**
     * 임시 인증 토큰을 생성합니다.
     */
    public String createTempToken(String provider, String providerId, String email, String name, Long expiredMs) {
        log.debug("임시 인증 토큰 생성 - 제공자: {}, providerId: {}, email: {}", provider, providerId, email);
        return buildToken(builder ->
                        builder.claim("provider", provider)
                                .claim("providerId", providerId)
                                .claim("email", email)
                                .claim("name", name)
                                .claim("registrationCompleted", false),
                expiredMs
        );
    }

    /**
     * 토큰 빌더를 사용하여 공통 토큰 생성 로직
     */
    private String buildToken(TokenBuilderCustomizer customizer, Long expiredMs) {
        try {
            var builder = Jwts.builder();
            customizer.customize(builder);
            return builder
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis() + expiredMs))
                    .signWith(secretKey)
                    .compact();
        } catch (Exception e) {
            log.error("JWT 토큰 생성 중 오류 발생: {}", e.getMessage());
            return null;
        }
    }

    @FunctionalInterface
    private interface TokenBuilderCustomizer {
        void customize(io.jsonwebtoken.JwtBuilder builder);
    }

    /**
     * 토큰에서 claims을 추출합니다.
     */
    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.error("토큰 클레임 추출 중 오류 발생: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 토큰이 만료되었는지 확인합니다.
     */
    public boolean isExpired(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (claims == null) return true;
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.error("토큰 만료 확인 중 오류 발생: {}", e.getMessage());
            return true;
        }
    }

    /**
     * 토큰의 남은 만료 시간을 초 단위로 반환합니다.
     */
    public long getExpiresIn(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (claims == null) return 0;
            Date expiration = claims.getExpiration();
            Date now = new Date();
            long diff = expiration.getTime() - now.getTime();
            return Math.max(0, diff / 1000);
        } catch (Exception e) {
            log.error("토큰 만료 시간 계산 중 오류 발생: {}", e.getMessage());
            return 0;
        }
    }

    // 토큰 정보 추출 메서드들
    public String getProvider(String token) { return getClaimValue(token, "provider"); }
    public String getSocialId(String token) { return getClaimValue(token, "socialId"); }
    public String getRole(String token) { return getClaimValue(token, "role"); }
    public String getEmail(String token) { return getClaimValue(token, "email"); }

    public UUID getUserId(String token) {
        String userIdStr = getClaimValue(token, "userId");
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    private String getClaimValue(String token, String claimName) {
        Claims claims = extractAllClaims(token);
        return claims != null ? claims.get(claimName, String.class) : null;
    }
}