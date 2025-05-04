package org.lucky0111.pettalk.service.user;

import lombok.RequiredArgsConstructor;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CommonUserServiceImpl implements CommonUserService {
    private final PetUserRepository userRepository;

    public PetUser findUserByIdOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND));
    }

    public Optional<PetUser> findUserById(UUID userId) {
        return userRepository.findById(userId);
    }
}
