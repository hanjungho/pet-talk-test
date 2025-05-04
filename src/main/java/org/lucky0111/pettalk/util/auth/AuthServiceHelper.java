package org.lucky0111.pettalk.util.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthServiceHelper {

    private final JWTUtil jwtUtil;
    private final PetUserRepository userRepository;

    /**
     * JWT 토큰 추출
     */
    public String extractJwtToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 현재 인증된 사용자의 UUID 가져오기
     */
    public UUID getCurrentUserUUID(HttpServletRequest request) {
        String token = extractJwtToken(request);
        if (token == null) {
            throw new CustomException("인증 토큰을 찾을 수 없습니다.", HttpStatus.UNAUTHORIZED);
        }

        UUID userId = jwtUtil.getUserId(token);
        if (userId == null) {
            throw new CustomException("유효하지 않은 토큰입니다.", HttpStatus.UNAUTHORIZED);
        }
        return userId;
    }

    /**
     * 현재 사용자 엔티티 가져오기
     */
    public PetUser getCurrentUser(HttpServletRequest request) {
        UUID currentUserUUID = getCurrentUserUUID(request);
        return userRepository.findById(currentUserUUID)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND));
    }

    /**
     * 인증 확인
     */
    public void validateAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new CustomException("인증 정보가 없습니다.", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 사용자 데이터 맵 생성
     */
    public Map<String, Object> createUserDataMap(PetUser user) {
        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getUserId());
        userData.put("email", user.getEmail());
        userData.put("name", user.getName());
        userData.put("nickname", user.getNickname());
        userData.put("profileImageUrl", user.getProfileImageUrl());
        userData.put("role", user.getRole());
        return userData;
    }
}