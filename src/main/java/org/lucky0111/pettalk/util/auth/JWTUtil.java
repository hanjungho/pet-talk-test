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
@RequiredArgsConstructor
public class JWTUtil {

    private final JWTTokenProvider tokenProvider;
    private final JWTTokenManager tokenManager;

    @Value("${spring.jwt.access-token-expiration-ms}")
    private Long accessTokenExpirationMs; // Default 1 hour
    @Value("${spring.jwt.refresh-token-expiration-days}")
    private Integer refreshTokenExpirationDays; // Default 30 days

    // 토큰 생성 메서드들 - 모두 JWTTokenProvider로 위임
    /**
     * JWT를 생성합니다.
     */
    public String createJwt(String provider, String socialId, UUID userId, String role, Long expiredMs) {
        return tokenProvider.createJwt(provider, socialId, userId, role, expiredMs);
    }

    /**
     * JWT를 생성합니다. 이메일 포함
     */
    public String createJwtWithEmail(String provider, String socialId, UUID userId, String role, String email, Long expiredMs) {
        return tokenProvider.createJwtWithEmail(provider, socialId, userId, role, email, expiredMs);
    }

    /**
     * 임시 토큰을 생성합니다.
     */
    public String createTempToken(String provider, String providerId, String email, String name, Long expiredMs) {
        return tokenProvider.createTempToken(provider, providerId, email, name, expiredMs);
    }

    // 토큰 검증 메서드들 - 모두 JWTTokenProvider로 위임
    public boolean isExpired(String token) { return tokenProvider.isExpired(token); }
    public long getExpiresIn(String token) { return tokenProvider.getExpiresIn(token); }
    public String getProvider(String token) { return tokenProvider.getProvider(token); }
    public String getSocialId(String token) { return tokenProvider.getSocialId(token); }
    public String getRole(String token) { return tokenProvider.getRole(token); }
    public UUID getUserId(String token) { return tokenProvider.getUserId(token); }
    public String getEmail(String token) { return tokenProvider.getEmail(token); }

    // 리프레시 토큰 관리 - 모두 JWTTokenManager로 위임
    /**
     * 리프레시 토큰을 생성합니다.
     */
    public String generateRefreshToken(PetUser user, Integer refreshTokenExpirationDays) {
        return tokenManager.generateRefreshToken(user, refreshTokenExpirationDays);
    }

    /**
     * 리프레시 토큰을 폐기합니다.
     */
    public boolean revokeRefreshToken(String refreshToken) {
        return tokenManager.revokeRefreshToken(refreshToken);
    }

    /**
     * 사용자의 모든 리프레시 토큰을 폐기합니다.
     */
    public void revokeAllUserTokens(UUID userId) {
        tokenManager.revokeAllUserTokens(userId);
    }

    /**
     * 만료된 리프레시 토큰을 제거합니다.
     */
    public void removeExpiredTokens() {
        tokenManager.removeExpiredTokens();
    }

    /**
     * 폐기된 리프레시 토큰을 제거합니다.
     */
    public void removeRevokedTokens() {
        tokenManager.removeRevokedTokens();
    }

    /**
     * 임시 토큰 정보를 추출합니다.
     */
    public OAuthTempTokenDTO getTempTokenInfo(String token) {
        try {
            Claims claims = tokenProvider.extractAllClaims(token);
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

    /**
     * 액세스 토큰과 리프레시 토큰을 생성합니다.
     */
    public TokenDTO generateTokenPair(PetUser user) {
        String accessToken = user.getEmail() != null ?
                createJwtWithEmail(user.getProvider(), user.getSocialId(), user.getUserId(),
                        user.getRole(), user.getEmail(), accessTokenExpirationMs) :
                createJwt(user.getProvider(), user.getSocialId(), user.getUserId(),
                        user.getRole(), accessTokenExpirationMs);

        String refreshToken = generateRefreshToken(user, refreshTokenExpirationDays);
        return new TokenDTO(accessToken, refreshToken, accessTokenExpirationMs / 1000);
    }

    /**
     * 리프레시 토큰으로 새로운 액세스 토큰을 생성합니다.
     */
    public Optional<TokenDTO> refreshAccessToken(String refreshToken) {
        return tokenManager.validateAndGetRefreshToken(refreshToken)
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
}