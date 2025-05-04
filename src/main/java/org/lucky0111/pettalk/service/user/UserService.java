package org.lucky0111.pettalk.service.user;

import jakarta.servlet.http.HttpServletRequest;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.auth.OAuthTempTokenDTO;
import org.lucky0111.pettalk.domain.dto.auth.UserRegistrationDTO;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;

import java.util.Optional;
import java.util.UUID;

public interface UserService {
    /**
     * 사용자 ID로 사용자를 찾고, 없으면 예외를 던집니다.
     *
     * @param userId 사용자 ID
     * @return PetUser 객체
     */
    PetUser findUserByIdOrThrow(UUID userId);

    /**
     * 사용자 ID로 사용자를 찾습니다.
     *
     * @param userId 사용자 ID
     * @return Optional<PetUser>
     */
    Optional<PetUser> findUserById(UUID userId);

    /**
     * 사용자를 탈퇴 처리합니다.
     *
     * @param userId 사용자 ID
     * @return true if withdrawal is successful, false otherwise
     */
    boolean withdrawUser(UUID userId);

    /**
     * 사용자 프로필을 업데이트합니다.
     *
     * @param userId            사용자 ID
     * @param profileUpdateDTO  프로필 업데이트 DTO
     * @return 업데이트된 PetUser 객체
     */
    PetUser updateProfile(UUID userId, ProfileUpdateDTO profileUpdateDTO);

    /**
     * 현재 사용자의 UUID를 요청에서 가져옵니다.
     *
     * @param request HTTP 요청
     * @return 현재 사용자 UUID
     */
    UUID getCurrentUserUUIDFromRequest(HttpServletRequest request);

    /**
     * 현재 사용자의 정보를 요청에서 가져옵니다.
     *
     * @param request HTTP 요청
     * @return 현재 사용자 PetUser 객체
     */
    PetUser getCurrentUserFromRequest(HttpServletRequest request);

    /**
     * OAuth2 사용자 정보를 기반으로 사용자를 찾거나 생성합니다.
     *
     * @param oAuth2User OAuth2 사용자 정보
     * @return PetUser 객체
     */
    PetUser findOrCreateUserFromOAuth2(CustomOAuth2User oAuth2User);

    /**
     * 사용자를 저장합니다.
     *
     * @param user PetUser 객체
     * @return 저장된 PetUser 객체
     */
    PetUser saveUser(PetUser user);

    /**
     * OAuth 임시 토큰 정보를 기반으로 사용자를 찾거나 생성합니다.
     *
     * @param tempTokenInfo   OAuth 임시 토큰 정보
     * @param registrationDTO 사용자 등록 DTO
     * @return PetUser 객체
     */
    PetUser findOrCreateUserFromOAuth(OAuthTempTokenDTO tempTokenInfo, UserRegistrationDTO registrationDTO);

    /**
     * 사용자의 상태를 검증합니다.
     *
     * @param user PetUser 객체
     * @throws CustomException 사용자 상태가 비활성화된 경우 예외 발생
     */
    void validateUserStatus(PetUser user);

    /**
     * 닉네임의 사용 가능 여부를 확인합니다.
     *
     * @param nickname 닉네임
     * @return true if available, false otherwise
     */
    boolean checkNicknameAvailability(String nickname);
}