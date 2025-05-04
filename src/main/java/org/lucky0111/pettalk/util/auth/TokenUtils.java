package org.lucky0111.pettalk.util.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.lucky0111.pettalk.exception.CustomException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenUtils {
    private final JWTUtil jwtUtil;

    public String extractJwtToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String extractJwtTokenOrThrow(HttpServletRequest request) {
        String token = extractJwtToken(request);
        if (token == null) {
            throw new CustomException("인증 토큰을 찾을 수 없습니다.", HttpStatus.UNAUTHORIZED);
        }
        return token;
    }

    public UUID getCurrentUserUUID(HttpServletRequest request) {
        String token = extractJwtTokenOrThrow(request);
        return jwtUtil.getUserId(token);
    }
}