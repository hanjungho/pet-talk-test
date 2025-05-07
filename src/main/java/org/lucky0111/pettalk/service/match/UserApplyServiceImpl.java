package org.lucky0111.pettalk.service.match;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.common.ErrorCode;
import org.lucky0111.pettalk.domain.common.ApplyStatus;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.match.UserApplyRequestDTO;
import org.lucky0111.pettalk.domain.dto.match.UserApplyResponseDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.domain.entity.trainer.Trainer;
import org.lucky0111.pettalk.domain.entity.match.UserApply;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.match.UserApplyRepository;
import org.lucky0111.pettalk.repository.trainer.TrainerRepository;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserApplyServiceImpl implements UserApplyService {

    private final UserApplyRepository userApplyRepository;
    private final PetUserRepository petUserRepository;
    private final TrainerRepository trainerRepository;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    @Transactional
    public UserApplyResponseDTO createApply(UserApplyRequestDTO requestDTO) {
        PetUser currentUser = getCurrentUser();
        Trainer trainer = findTrainerByName(requestDTO.trainerName());

        validateNoPendingApply(currentUser.getUserId(), trainer.getTrainerId());

        UserApply userApply = buildUserApplyFromRequest(requestDTO, currentUser, trainer);
        UserApply savedApply = userApplyRepository.save(userApply);

        return convertToResponseDTO(savedApply);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserApplyResponseDTO> getUserApplies() {
        PetUser currentUser = getCurrentUser();
        List<UserApply> userApplies = userApplyRepository.findByPetUser_UserIdWithRelations(currentUser.getUserId());
        return convertToResponseDTOList(userApplies);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserApplyResponseDTO> getTrainerApplies() {
        PetUser currentUser = getCurrentUser();
        List<UserApply> trainerApplies = userApplyRepository.findByTrainer_TrainerId(currentUser.getUserId());
        return convertToResponseDTOList(trainerApplies);
    }

    @Override
    @Transactional
    public UserApplyResponseDTO updateApplyStatus(Long applyId, ApplyStatus applyStatus) {
        PetUser currentUser = getCurrentUser();
        UserApply userApply = findApplyById(applyId);

        validateTrainerPermission(userApply, currentUser.getUserId());

        userApply.setApplyStatus(applyStatus);
        UserApply updatedApply = userApplyRepository.save(userApply);

        return convertToResponseDTO(updatedApply);
    }

    @Override
    @Transactional
    public UserApplyResponseDTO deleteApply(Long applyId) {
        PetUser currentUser = getCurrentUser();
        UserApply userApply = findApplyById(applyId);

        validateUserPermission(userApply, currentUser.getUserId());

        UserApplyResponseDTO responseDTO = convertToResponseDTO(userApply);
        userApplyRepository.delete(userApply);

        return responseDTO;
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserApplyResponseDTO> getUserAppliesByStatus(ApplyStatus applyStatus) {
        PetUser currentUser = getCurrentUser();
        List<UserApply> userApplies = userApplyRepository.findByPetUser_UserIdAndApplyStatusWithRelations(
                currentUser.getUserId(), applyStatus);

        return convertToResponseDTOList(userApplies);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserApplyResponseDTO> getUserAppliesPaged(Pageable pageable) {
        PetUser currentUser = getCurrentUser();
        Page<UserApply> userAppliesPage = userApplyRepository.findByPetUser_UserIdWithRelationsPaged(
                currentUser.getUserId(), pageable);

        return userAppliesPage.map(this::convertToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserApplyResponseDTO> getUserAppliesByStatusPaged(ApplyStatus applyStatus, Pageable pageable) {
        PetUser currentUser = getCurrentUser();
        Page<UserApply> userAppliesPage = userApplyRepository.findByPetUser_UserIdAndStatusWithRelationsPaged(
                currentUser.getUserId(), applyStatus, pageable);

        return userAppliesPage.map(this::convertToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserApplyResponseDTO> getTrainerAppliesByStatus(ApplyStatus applyStatus) {
        PetUser currentUser = getCurrentUser();
        List<UserApply> trainerApplies = userApplyRepository.findByTrainer_TrainerIdAndApplyStatusWithRelations(
                currentUser.getUserId(), applyStatus);

        return convertToResponseDTOList(trainerApplies);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserApplyResponseDTO> getTrainerAppliesPaged(Pageable pageable) {
        PetUser currentUser = getCurrentUser();
        Page<UserApply> trainerAppliesPage = userApplyRepository.findByTrainer_TrainerIdWithRelationsPaged(
                currentUser.getUserId(), pageable);

        return trainerAppliesPage.map(this::convertToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserApplyResponseDTO> getTrainerAppliesByStatusPaged(ApplyStatus applyStatus, Pageable pageable) {
        PetUser currentUser = getCurrentUser();
        Page<UserApply> trainerAppliesPage = userApplyRepository.findByTrainer_TrainerIdAndStatusWithRelationsPaged(
                currentUser.getUserId(), applyStatus, pageable);

        return trainerAppliesPage.map(this::convertToResponseDTO);
    }

    // 리팩토링된 private 메소드들

    private UserApply buildUserApplyFromRequest(UserApplyRequestDTO requestDTO, PetUser petUser, Trainer trainer) {
        UserApply userApply = new UserApply();
        userApply.setPetUser(petUser);
        userApply.setTrainer(trainer);
        userApply.setPetType(requestDTO.petType());
        userApply.setPetBreed(requestDTO.petBreed());
        userApply.setPetMonthAge(requestDTO.petMonthAge());
        userApply.setContent(requestDTO.content());
        userApply.setImageUrl(requestDTO.imageUrl());
        userApply.setApplyStatus(ApplyStatus.PENDING);
        return userApply;
    }

    private void validateNoPendingApply(UUID userId, UUID trainerId) {
        if (userApplyRepository.existsByPetUser_userIdAndTrainer_trainerIdAndApplyStatus(
                userId, trainerId, ApplyStatus.PENDING)) {
            throw new CustomException(ErrorCode.APPLY_ALREADY_EXISTS);
        }
    }

    private Trainer findTrainerByName(String trainerName) {
        return trainerRepository.findByUser_Nickname(trainerName)
                .orElseThrow(() -> new CustomException(ErrorCode.APPLY_NOT_FOUND));
    }

    private UserApply findApplyById(Long applyId) {
        return userApplyRepository.findByIdWithRelations(applyId)
                .orElseThrow(() -> new CustomException(ErrorCode.APPLY_NOT_FOUND));
    }

    private void validateTrainerPermission(UserApply userApply, UUID currentUserId) {
        if (!userApply.getTrainer().getTrainerId().equals(currentUserId)) {
            throw new CustomException(ErrorCode.PERMISSION_DENIED);
        }
    }

    private void validateUserPermission(UserApply userApply, UUID currentUserId) {
        if (!userApply.getPetUser().getUserId().equals(currentUserId)) {
            throw new CustomException(ErrorCode.PERMISSION_DENIED);
        }
    }

    private List<UserApplyResponseDTO> convertToResponseDTOList(List<UserApply> userApplies) {
        return userApplies.stream()
                .map(this::convertToResponseDTO)
                .collect(Collectors.toList());
    }

    private UUID getCurrentUserUUID() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() &&
                authentication.getPrincipal() instanceof CustomOAuth2User userDetails) {
            return userDetails.getUserId();
        }

        throw new CustomException(ErrorCode.UNAUTHORIZED);
    }

    private PetUser getCurrentUser() {
        UUID currentUserUUID = getCurrentUserUUID();
        return petUserRepository.findById(currentUserUUID)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    }

    private UserApplyResponseDTO convertToResponseDTO(UserApply userApply) {
        String createdAtStr = formatDateTime(userApply.getCreatedAt());
        String updatedAtStr = formatDateTime(userApply.getUpdatedAt());

        return new UserApplyResponseDTO(
                userApply.getApplyId(),
                userApply.getPetUser().getName(),
                userApply.getTrainer().getUser().getName(),
                userApply.getPetType(),
                userApply.getPetBreed(),
                userApply.getPetMonthAge(),
                userApply.getContent(),
                userApply.getImageUrl(),
                userApply.getApplyStatus(),
                createdAtStr,
                updatedAtStr
        );
    }

    private String formatDateTime(java.time.LocalDateTime dateTime) {
        return dateTime != null ? dateTime.format(DATE_FORMATTER) : null;
    }
}