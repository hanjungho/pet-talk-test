package org.lucky0111.pettalk.scheduler.auth;

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

    /**
     * 매일 새벽 2시에 만료된 리프레시 토큰과 폐기된 리프레시 토큰을 정리하는 스케줄러
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupTokens() {
        System.out.println("Running scheduled task to clean up expired and revoked refresh tokens");
        jwtUtil.removeExpiredTokens();
        jwtUtil.removeRevokedTokens(); // 폐기된 토큰도 정리
    }
}