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

    /**
     * JWT 토큰을 추출합니다.
     *
     * @param request HTTP 요청
     * @return JWT 토큰
     */
    public String extractJwtToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * JWT 토큰을 추출하고, 없으면 예외를 던집니다.
     *
     * @param request HTTP 요청
     * @return JWT 토큰
     * @throws CustomException 인증 토큰을 찾을 수 없을 때 발생
     */
    public String extractJwtTokenOrThrow(HttpServletRequest request) {
        String token = extractJwtToken(request);
        if (token == null) {
            throw new CustomException("인증 토큰을 찾을 수 없습니다.", HttpStatus.UNAUTHORIZED);
        }
        return token;
    }

    /**
     * 현재 사용자의 UUID를 가져옵니다.
     *
     * @param request HTTP 요청
     * @return 현재 사용자의 UUID
     * @throws CustomException 인증 토큰을 찾을 수 없을 때 발생
     */
    public UUID getCurrentUserUUID(HttpServletRequest request) {
        String token = extractJwtTokenOrThrow(request);
        return jwtUtil.getUserId(token);
    }
}