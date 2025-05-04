package org.lucky0111.pettalk.service.user;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.util.auth.StringUtils;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final PetUserRepository userRepository;
    private final CommonUserService commonUserService;

    @Transactional
    public boolean withdrawUser(UUID userId) {
        Optional<PetUser> userOptional = commonUserService.findUserById(userId);

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
        Optional<PetUser> userOptional = commonUserService.findUserById(userId);

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