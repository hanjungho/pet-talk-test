package org.lucky0111.pettalk.service.user;

import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.springframework.http.HttpStatus;

import java.util.Optional;
import java.util.UUID;

public interface CommonUserService {
    PetUser findUserByIdOrThrow(UUID userId);
    Optional<PetUser> findUserById(UUID userId);
}
