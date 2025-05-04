package org.lucky0111.pettalk.service.user;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.auth.OAuthTempTokenDTO;
import org.lucky0111.pettalk.domain.dto.auth.UserRegistrationDTO;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.util.auth.StringUtils;
import org.lucky0111.pettalk.util.auth.TokenUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final PetUserRepository userRepository;
    private final TokenUtils tokenUtils;

    @Override
    public PetUser findUserByIdOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND));
    }

    @Override
    public Optional<PetUser> findUserById(UUID userId) {
        return userRepository.findById(userId);
    }

    @Override
    @Transactional
    public boolean withdrawUser(UUID userId) {
        Optional<PetUser> userOptional = findUserById(userId);
        if (userOptional.isPresent()) {
            PetUser user = userOptional.get();
            user.setStatus("WITHDRAWN");
            user.setSocialId(null);
            saveUser(user);
            return true;
        }
        return false;
    }

    @Override
    @Transactional
    public PetUser updateProfile(UUID userId, ProfileUpdateDTO profileUpdateDTO) {
        Optional<PetUser> userOptional = findUserById(userId);
        if (userOptional.isPresent()) {
            PetUser user = userOptional.get();
            if (StringUtils.isNotEmpty(profileUpdateDTO.nickname())) {
                user.setNickname(profileUpdateDTO.nickname());
            }
            if (StringUtils.isNotEmpty(profileUpdateDTO.profileImageUrl())) {
                user.setProfileImageUrl(profileUpdateDTO.profileImageUrl());
            }
            return saveUser(user);
        }
        return null;
    }

    @Override
    public UUID getCurrentUserUUIDFromRequest(HttpServletRequest request) {
        return tokenUtils.getCurrentUserUUID(request);
    }

    @Override
    public PetUser getCurrentUserFromRequest(HttpServletRequest request) {
        UUID currentUserUUID = getCurrentUserUUIDFromRequest(request);
        return findUserByIdOrThrow(currentUserUUID);
    }

    @Override
    public PetUser findOrCreateUserFromOAuth2(CustomOAuth2User oAuth2User) {
        String provider = oAuth2User.getProvider();
        String socialId = oAuth2User.getSocialId();

        PetUser existData = userRepository.findByProviderAndSocialId(provider, socialId);

        if (existData == null) {
            log.info("신규 사용자 - 첫 로그인");
            return null;
        } else {
            log.info("기존 사용자 정보: {}, {}", existData.getUserId(), existData.getRole());
            return existData;
        }
    }

    @Override
    @Transactional
    public PetUser saveUser(PetUser user) {
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public PetUser findOrCreateUserFromOAuth(OAuthTempTokenDTO tempTokenInfo, UserRegistrationDTO registrationDTO) {
        PetUser existingUser = userRepository.findByProviderAndSocialId(
                tempTokenInfo.provider(), tempTokenInfo.providerId());

        PetUser petUser;

        if (existingUser != null) {
            // 기존 사용자 정보 업데이트
            petUser = existingUser;
            petUser.setName(registrationDTO.name());
            petUser.setNickname(registrationDTO.nickname());
            petUser.setProfileImageUrl(registrationDTO.profileImageUrl());
            log.info("기존 사용자 정보 업데이트: {}, {}", petUser.getUserId(), petUser.getName());
        } else {
            // 새 사용자 생성
            petUser = new PetUser();
            petUser.setProvider(tempTokenInfo.provider());
            petUser.setSocialId(tempTokenInfo.providerId());
            petUser.setEmail(tempTokenInfo.email());
            petUser.setName(registrationDTO.name());
            petUser.setNickname(registrationDTO.nickname());
            petUser.setProfileImageUrl(registrationDTO.profileImageUrl());
            petUser.setRole("USER");
            petUser.setStatus("ACTIVE");
            log.info("새 사용자 정보 생성: {}, {}, {}",
                    petUser.getName(), petUser.getProvider(), petUser.getSocialId());
        }
        return petUser;
    }

    @Override
    public void validateUserStatus(PetUser user) {
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new CustomException("비활성화된 사용자입니다.", HttpStatus.FORBIDDEN);
        }
    }

    @Override
    public boolean checkNicknameAvailability(String nickname) {
        return !userRepository.existsByNickname(nickname);
    }
}