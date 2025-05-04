package org.lucky0111.pettalk.util.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.auth.OAuthTempTokenDTO;
import org.lucky0111.pettalk.domain.dto.auth.TokenDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.domain.entity.auth.RefreshToken;
import org.lucky0111.pettalk.repository.auth.RefreshTokenRepository;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class JWTUtil {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecretKey secretKey;

    @Value("${spring.jwt.access-token-expiration-ms:3600000}")
    private Long accessTokenExpirationMs; // Default 1 hour

    @Value("${spring.jwt.refresh-token-expiration-days:30}")
    private Integer refreshTokenExpirationDays; // Default 30 days

    // 단일 생성자로 변경
    public JWTUtil(@Value("${spring.jwt.secret}") String secret,
                   RefreshTokenRepository refreshTokenRepository) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm());
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // Token Claims 추출
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

    // Token 생성 메서드들
    public String createJwt(String provider, String socialId, UUID userId, String role, Long expiredMs) {
        return buildJWT(provider, socialId, userId, role, null, expiredMs);
    }

    public String createJwtWithEmail(String provider, String socialId, UUID userId, String role, String email, Long expiredMs) {
        return buildJWT(provider, socialId, userId, role, email, expiredMs);
    }

    public String createTempToken(String provider, String providerId, String email, String name, Long expiredMs) {
        try {
            return Jwts.builder()
                    .claim("provider", provider)
                    .claim("providerId", providerId)
                    .claim("email", email)
                    .claim("name", name)
                    .claim("registrationCompleted", false)
                    .issuedAt(new Date(System.currentTimeMillis()))
                    .expiration(new Date(System.currentTimeMillis() + expiredMs))
                    .signWith(secretKey)
                    .compact();
        } catch (Exception e) {
            log.error("임시 인증 토큰 생성 중 오류 발생: {}", e.getMessage());
            return null;
        }
    }

    private String buildJWT(String provider, String socialId, UUID userId, String role, String email, Long expiredMs) {
        try {
            var builder = Jwts.builder()
                    .claim("provider", provider)
                    .claim("socialId", socialId)
                    .claim("userId", userId.toString())
                    .claim("role", role);

            if (email != null) {
                builder.claim("email", email);
            }

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

    // Token 유효성 검사
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

    // Token 정보 추출 메서드들
    public String getProvider(String token) {
        return getClaimValue(token, "provider");
    }

    public String getSocialId(String token) {
        return getClaimValue(token, "socialId");
    }

    public String getRole(String token) {
        return getClaimValue(token, "role");
    }

    public UUID getUserId(String token) {
        String userIdStr = getClaimValue(token, "userId");
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    public String getEmail(String token) {
        return getClaimValue(token, "email");
    }

    private String getClaimValue(String token, String claimName) {
        Claims claims = extractAllClaims(token);
        return claims != null ? claims.get(claimName, String.class) : null;
    }

    // OAuth 임시 토큰 처리
    public OAuthTempTokenDTO getTempTokenInfo(String token) {
        try {
            var claims = extractAllClaims(token);
            if (claims == null) return null;

            return OAuthTempTokenDTO.builder()
                    .provider(claims.get("provider", String.class))
                    .providerId(claims.get("providerId", String.class))
                    .email(claims.get("email", String.class))
                    .name(claims.get("name", String.class))
                    .registrationCompleted(claims.get("registrationCompleted", Boolean.class))
                    .build();
        } catch (Exception e) {
            log.error("임시 토큰 파싱 중 오류 발생: {}", e.getMessage());
            return null;
        }
    }

    // Refresh Token 관리
    @Transactional
    public String generateRefreshToken(PetUser user) {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        LocalDateTime expiryDate = LocalDateTime.now().plus(refreshTokenExpirationDays, ChronoUnit.DAYS);
        RefreshToken refreshToken = new RefreshToken(token, user, expiryDate);
        refreshTokenRepository.save(refreshToken);
        return token;
    }

    @Transactional
    public TokenDTO generateTokenPair(PetUser user) {
        String accessToken = user.getEmail() != null ?
                createJwtWithEmail(user.getProvider(), user.getSocialId(), user.getUserId(),
                        user.getRole(), user.getEmail(), accessTokenExpirationMs) :
                createJwt(user.getProvider(), user.getSocialId(), user.getUserId(),
                        user.getRole(), accessTokenExpirationMs);

        String refreshToken = generateRefreshToken(user);
        return new TokenDTO(accessToken, refreshToken, accessTokenExpirationMs / 1000);
    }

    @Transactional
    public Optional<TokenDTO> refreshAccessToken(String refreshToken) {
        return refreshTokenRepository.findByToken(refreshToken)
                .filter(RefreshToken::isValid)
                .map(token -> {
                    PetUser user = token.getUser();
                    String newAccessToken = user.getEmail() != null ?
                            createJwtWithEmail(user.getProvider(), user.getSocialId(), user.getUserId(),
                                    user.getRole(), user.getEmail(), accessTokenExpirationMs) :
                            createJwt(user.getProvider(), user.getSocialId(), user.getUserId(),
                                    user.getRole(), accessTokenExpirationMs);
                    return new TokenDTO(newAccessToken, refreshToken, accessTokenExpirationMs / 1000);
                });
    }

    @Transactional
    public boolean revokeRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByToken(refreshToken)
                .map(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public void revokeAllUserTokens(UUID userId) {
        refreshTokenRepository.revokeAllByUser(userId);
    }

    @Transactional
    public void removeExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredTokens(LocalDateTime.now());
    }

    @Transactional
    public void removeRevokedTokens() {
        refreshTokenRepository.deleteAllRevokedTokens();
    }
}