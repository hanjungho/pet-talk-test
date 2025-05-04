package org.lucky0111.pettalk.config.auth;

import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class TokenCleanupScheduler {

    private final JWTUtil jwtUtil;

    public TokenCleanupScheduler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupTokens() {
        System.out.println("Running scheduled task to clean up expired and revoked refresh tokens");
        jwtUtil.removeExpiredTokens();
        jwtUtil.removeRevokedTokens(); // 폐기된 토큰도 정리
    }
}