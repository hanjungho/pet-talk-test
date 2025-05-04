package org.lucky0111.pettalk.service.user;

import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;

import java.util.Optional;
import java.util.UUID;

public interface UserService {
    /**
     * 사용자 ID로 사용자를 찾고, 없으면 예외를 던집니다.
     */
    PetUser findUserByIdOrThrow(UUID userId);

    /**
     * 사용자 ID로 사용자를 찾습니다.
     */
    Optional<PetUser> findUserById(UUID userId);

    /**
     * 사용자 탈퇴 처리
     */
    boolean withdrawUser(UUID userId);

    /**
     * 사용자 프로필 업데이트
     */
    PetUser updateProfile(UUID userId, ProfileUpdateDTO profileUpdateDTO);
}