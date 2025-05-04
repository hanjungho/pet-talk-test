package org.lucky0111.pettalk.service.user;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.util.auth.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final PetUserRepository userRepository;
    private final UserService UserService;

    /**
     * 사용자 ID로 사용자를 찾고, 없으면 예외를 던집니다.
     *
     * @param userId 사용자 ID
     * @return 사용자가 존재하면 해당 사용자, 없으면 예외
     */
    public PetUser findUserByIdOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND));
    }

    /**
     * 사용자 ID로 사용자를 찾습니다.
     *
     * @param userId 사용자 ID
     * @return 사용자가 존재하면 Optional에 포함된 사용자, 없으면 빈 Optional
     */
    public Optional<PetUser> findUserById(UUID userId) {
        return userRepository.findById(userId);
    }

    @Transactional
    public boolean withdrawUser(UUID userId) {
        Optional<PetUser> userOptional = UserService.findUserById(userId);

        if (userOptional.isPresent()) {
            PetUser user = userOptional.get();
            withdrawUserProcess(user);
            return true;
        }

        return false;
    }

    /**
     * 사용자 탈퇴 처리
     */
    private void withdrawUserProcess(PetUser user) {
        updateUserStatus(user);
        removeUserSocialId(user);
        saveUser(user);
    }

    /**
     * 사용자 상태 업데이트
     */
    private void updateUserStatus(PetUser user) {
        user.setStatus("WITHDRAWN");
    }

    /**
     * 사용자 소셜 ID 제거
     */
    private void removeUserSocialId(PetUser user) {
        user.setSocialId(null);
    }

    @Transactional
    public PetUser updateProfile(UUID userId, ProfileUpdateDTO profileUpdateDTO) {
        Optional<PetUser> userOptional = UserService.findUserById(userId);

        if (userOptional.isPresent()) {
            PetUser user = userOptional.get();
            updateUserProfile(user, profileUpdateDTO);
            return saveUser(user);
        }

        return null;
    }

    /**
     * 사용자 저장
     */
    private PetUser saveUser(PetUser user) {
        return userRepository.save(user);
    }

    /**
     * 사용자 프로필 업데이트
     */
    private void updateUserProfile(PetUser user, ProfileUpdateDTO profileUpdateDTO) {
        updateNicknameIfPresent(user, profileUpdateDTO.nickname());
        updateProfileImageUrlIfPresent(user, profileUpdateDTO.profileImageUrl());
    }

    /**
     * 닉네임이 존재하면 업데이트
     */
    private void updateNicknameIfPresent(PetUser user, String nickname) {
        if (StringUtils.isNotEmpty(nickname)) {
            user.setNickname(nickname);
        }
    }

    /**
     * 프로필 이미지 URL이 존재하면 업데이트
     */
    private void updateProfileImageUrlIfPresent(PetUser user, String profileImageUrl) {
        if (StringUtils.isNotEmpty(profileImageUrl)) {
            user.setProfileImageUrl(profileImageUrl);
        }
    }
}