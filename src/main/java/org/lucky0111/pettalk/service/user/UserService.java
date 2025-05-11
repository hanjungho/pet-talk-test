package org.lucky0111.pettalk.service.user;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.lucky0111.pettalk.domain.common.ErrorCode;
import org.lucky0111.pettalk.domain.common.UserRole;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.user.UserRegisterDTO;
import org.lucky0111.pettalk.domain.dto.user.UserResponseDTO;
import org.lucky0111.pettalk.domain.dto.user.UserUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.service.file.FileUploaderService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final PetUserRepository userRepository;
    private final FileUploaderService fileUploaderService;

    @Transactional
    public boolean withdrawUser(UUID userId) {
        Optional<PetUser> userOptional = userRepository.findById(userId);

        if (userOptional.isPresent()) {
            PetUser user = userOptional.get();
            // 실제 삭제 대신 상태를 변경하는 논리적 삭제 (Soft Delete) 방식 적용
            user.setStatus("WITHDRAWN");
            user.setSocialId(null);
            userRepository.save(user);
            return true;
        }

        return false;
    }

    @Transactional
    public PetUser updateUserProfile(UserRegisterDTO userRegisterDTO, Authentication authentication) {
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        String username = customOAuth2User.getName();

        PetUser petUser = userRepository.findById(UUID.fromString(username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id:" + username));

        petUser.setRole(UserRole.USER);

        if (userRegisterDTO.name() != null && !userRegisterDTO.name().isBlank()) {
            petUser.setName(userRegisterDTO.name());
        }
        if (userRegisterDTO.nickname() != null && !userRegisterDTO.nickname().isBlank()) {
            if (userRepository.existsByNickname(userRegisterDTO.nickname())) {
                throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
            }
            petUser.setNickname(userRegisterDTO.nickname());
        }
        if (userRegisterDTO.profileImageUrl() != null && !userRegisterDTO.profileImageUrl().isBlank()) {
            petUser.setProfileImageUrl(userRegisterDTO.profileImageUrl());
        }

        return userRepository.save(petUser);
    }

    public UserUpdateDTO updateUser(UserUpdateDTO requestDTO) {
        UUID userId = getCurrentUserUUID();

        PetUser petUser = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id:" + userId));

        petUser.setName(requestDTO.name());
        petUser.setNickname(requestDTO.nickname());

        userRepository.save(petUser);

        return requestDTO;
    }

    public UserUpdateDTO updateUserImage(MultipartFile image) throws IOException {
        UUID userId = getCurrentUserUUID();

        PetUser petUser = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id:" + userId));

        String folderName = "profile/";

        String imageUrl = fileUploaderService.uploadFile(image,folderName);
        petUser.setProfileImageUrl(imageUrl);
        userRepository.save(petUser);

        return new UserUpdateDTO(petUser.getName(), petUser.getNickname(), imageUrl) ;
    }

    public UserResponseDTO getUserById() {
        UUID userId = getCurrentUserUUID();

        PetUser petUser = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id:" + userId));
        
        return UserResponseDTO.from(petUser);
    }

    private UUID getCurrentUserUUID() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() &&
                authentication.getPrincipal() instanceof CustomOAuth2User userDetails) {
            return userDetails.getUserId();
        }

        throw new CustomException(ErrorCode.UNAUTHORIZED);
    }
}