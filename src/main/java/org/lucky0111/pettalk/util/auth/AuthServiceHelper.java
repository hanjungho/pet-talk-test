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
        String bearerToken = extractBearerToken(request);
        return extractTokenFromBearer(bearerToken);
    }

    /**
     * Authorization 헤더에서 Bearer 토큰 추출
     */
    private String extractBearerToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    /**
     * Bearer 토큰에서 실제 토큰 값만 추출
     */
    private String extractTokenFromBearer(String bearerToken) {
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
        validateToken(token);
        return extractUserId(token);
    }

    /**
     * 토큰 유효성 검증
     */
    private void validateToken(String token) {
        if (token == null) {
            throw new CustomException("인증 토큰을 찾을 수 없습니다.", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 토큰에서 사용자 ID 추출
     */
    private UUID extractUserId(String token) {
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
        return findUserByUUID(currentUserUUID);
    }

    /**
     * UUID로 사용자 조회
     */
    private PetUser findUserByUUID(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND));
    }

    /**
     * 인증 확인
     */
    public void validateAuthentication() {
        Authentication authentication = getAuthenticationFromContext();
        checkAuthenticated(authentication);
    }

    /**
     * Security Context에서 인증 정보 가져오기
     */
    private Authentication getAuthenticationFromContext() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 인증 상태 확인
     */
    private void checkAuthenticated(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new CustomException("인증 정보가 없습니다.", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 사용자 데이터 맵 생성
     */
    public Map<String, Object> createUserDataMap(PetUser user) {
        return createUserProfileMap(user);
    }

    /**
     * 사용자 프로필 맵 생성
     */
    private Map<String, Object> createUserProfileMap(PetUser user) {
        Map<String, Object> userData = new HashMap<>();
        userData.put("id", getUserId(user));
        userData.put("email", getUserEmail(user));
        userData.put("name", getUserName(user));
        userData.put("nickname", getUserNickname(user));
        userData.put("profileImageUrl", getUserProfileImageUrl(user));
        userData.put("role", getUserRole(user));
        return userData;
    }

    /**
     * 사용자 ID 가져오기
     */
    private UUID getUserId(PetUser user) {
        return user.getUserId();
    }

    /**
     * 사용자 이메일 가져오기
     */
    private String getUserEmail(PetUser user) {
        return user.getEmail();
    }

    /**
     * 사용자 이름 가져오기
     */
    private String getUserName(PetUser user) {
        return user.getName();
    }

    /**
     * 사용자 닉네임 가져오기
     */
    private String getUserNickname(PetUser user) {
        return user.getNickname();
    }

    /**
     * 사용자 프로필 이미지 URL 가져오기
     */
    private String getUserProfileImageUrl(PetUser user) {
        return user.getProfileImageUrl();
    }

    /**
     * 사용자 역할 가져오기
     */
    private String getUserRole(PetUser user) {
        return user.getRole();
    }
}