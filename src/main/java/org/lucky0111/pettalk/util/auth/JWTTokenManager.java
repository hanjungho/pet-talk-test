package org.lucky0111.pettalk.util.auth;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.entity.auth.RefreshToken;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.repository.auth.RefreshTokenRepository;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * JWT 토큰 관리를 담당하는 클래스
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JWTTokenManager {

    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * 새 리프레시 토큰을 생성합니다.
     */
    @Transactional
    public String generateRefreshToken(PetUser user, Integer refreshTokenExpirationDays) {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        LocalDateTime expiryDate = LocalDateTime.now().plus(refreshTokenExpirationDays, ChronoUnit.DAYS);
        RefreshToken refreshToken = new RefreshToken(token, user, expiryDate);
        refreshTokenRepository.save(refreshToken);

        return token;
    }

    /**
     * 리프레시 토큰을 검증하고 반환합니다.
     */
    @Transactional
    public Optional<RefreshToken> validateAndGetRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(RefreshToken::isValid);
    }

    /**
     * 리프레시 토큰을 폐기합니다.
     */
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

    /**
     * 사용자의 모든 리프레시 토큰을 폐기합니다.
     */
    @Transactional
    public void revokeAllUserTokens(UUID userId) {
        refreshTokenRepository.revokeAllByUser(userId);
    }

    /**
     * 만료된 토큰을 제거합니다.
     */
    @Transactional
    public void removeExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredTokens(LocalDateTime.now());
    }

    /**
     * 폐기된 토큰을 제거합니다.
     */
    @Transactional
    public void removeRevokedTokens() {
        refreshTokenRepository.deleteAllRevokedTokens();
    }
}