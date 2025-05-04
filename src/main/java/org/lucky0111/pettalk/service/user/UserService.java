package org.lucky0111.pettalk.service.user;

import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;

import java.util.UUID;

public interface UserService {
    boolean withdrawUser(UUID userId);
    PetUser updateProfile(UUID userId, ProfileUpdateDTO profileUpdateDTO);
}