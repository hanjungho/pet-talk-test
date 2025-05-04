package org.lucky0111.pettalk.util.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.service.user.CommonUserService;
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
    private final CommonUserService commonUserService;
    private final TokenUtils tokenUtils;

    /**
     * JWT 토큰 추출
     */
    public String extractJwtToken(HttpServletRequest request) {
        return tokenUtils.extractJwtToken(request);
    }

    /**
     * 현재 인증된 사용자의 UUID 가져오기
     */
    public UUID getCurrentUserUUID(HttpServletRequest request) {
        return tokenUtils.getCurrentUserUUID(request);
    }

    /**
     * 현재 사용자 엔티티 가져오기
     */
    public PetUser getCurrentUser(HttpServletRequest request) {
        UUID currentUserUUID = getCurrentUserUUID(request);
        return commonUserService.findUserByIdOrThrow(currentUserUUID);
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