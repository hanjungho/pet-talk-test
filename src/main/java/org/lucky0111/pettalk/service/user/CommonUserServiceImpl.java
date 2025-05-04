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
}
