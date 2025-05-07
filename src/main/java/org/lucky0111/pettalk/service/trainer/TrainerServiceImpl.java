package org.lucky0111.pettalk.service.trainer;

import com.sun.jdi.request.DuplicateRequestException;
import lombok.RequiredArgsConstructor;
import org.lucky0111.pettalk.domain.common.UserRole;
import org.lucky0111.pettalk.domain.dto.review.ReviewStatsDTO;
import org.lucky0111.pettalk.domain.dto.trainer.CertificationDTO;
import org.lucky0111.pettalk.domain.dto.trainer.CertificationRequestDTO;
import org.lucky0111.pettalk.domain.dto.trainer.TrainerApplicationRequestDTO;
import org.lucky0111.pettalk.domain.dto.trainer.TrainerDTO;
import org.lucky0111.pettalk.domain.entity.trainer.Trainer;
import org.lucky0111.pettalk.domain.entity.common.Tag;
import org.lucky0111.pettalk.domain.entity.trainer.Certification;
import org.lucky0111.pettalk.domain.entity.trainer.TrainerTagRelation;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.common.TagRepository;
import org.lucky0111.pettalk.repository.review.ReviewRepository;
import org.lucky0111.pettalk.repository.trainer.CertificationRepository;
import org.lucky0111.pettalk.repository.trainer.TrainerRepository;
import org.lucky0111.pettalk.repository.trainer.TrainerTagRepository;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.service.file.FileUploaderService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.lucky0111.pettalk.domain.common.UserRole;


import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional //DB 작업이 하나의 트랜잭션으로 처리.

public class TrainerServiceImpl implements TrainerService {

    private final TrainerRepository trainerRepository;
    private final PetUserRepository petUserRepository;
    private final CertificationRepository certificationRepository;
    private final TrainerTagRepository trainerTagRepository;
    private final TagRepository tagRepository;
    private final ReviewRepository reviewRepository;
    private final FileUploaderService fileUploaderService;

    @Override
    public TrainerDTO getTrainerDetails(UUID trainerId) {
        // 1. Trainer 엔티티 조회 (ID는 UUID)
        Trainer trainer = trainerRepository.findById(trainerId)
                .orElseThrow(() -> new CustomException("Trainer not found with id: %s".formatted(trainerId), HttpStatus.NOT_FOUND));

        // 2. 연관된 PetUser 엔티티 조회 (Trainer 엔티티에 User user 필드가 있고 @OneToOne 관계로 매핑되었다고 가정)
        PetUser user = trainer.getUser();

        // 3. 자격증 목록 조회 (Trainer ID는 UUID)
        List<CertificationDTO> certificationDtoList = getCertificationDTOList(trainerId);

        // 4. 전문 분야(태그) 목록 조회 (Trainer ID는 UUID)
        List<String> specializationNames = getSpecializationNames(trainerId);

        // 5. 평점 및 후기 개수 조회 (ReviewRepository 사용, 인자 타입 UUID)
        ReviewStatsDTO reviewStatsDTO = getReviewStatsDTO(trainerId);

        // 6. 엔티티 -> DTO (Record) 매핑 및 반환
        return new TrainerDTO(
                trainer.getTrainerId(), // UUID 타입
                user != null ? user.getNickname() : null,
                user != null ? user.getProfileImageUrl() : null,
                user != null ? user.getEmail() : null, // email 필드 추가 (PetUser에 있다고 가정)
                trainer.getIntroduction(),
                trainer.getExperienceYears(),
                specializationNames, // 태그 이름 목록
                certificationDtoList, // 자격증 DTO 목록
                reviewStatsDTO.averageRating(),
                reviewStatsDTO.reviewCount()
        );
    }
    private List<CertificationDTO> getCertificationDTOList(UUID trainerId){
        List<Certification> certifications = certificationRepository.findByTrainer_TrainerId(trainerId);

        return certifications.stream()
                .map(CertificationDTO::fromEntity) // Certification 엔티티 -> CertificationDto Record 변환 (CertificationDto에 fromEntity 메소드 구현 필요)
                .toList();
    }

    private List<String> getSpecializationNames(UUID trainerId){
        List<TrainerTagRelation> trainerTags = trainerTagRepository.findByTrainer_TrainerId(trainerId);
        return trainerTags.stream()
                .map(TrainerTagRelation::getTag) // TrainerTag 엔티티에서 Tag 엔티티를 가져옴 (관계 매핑 필요)
                .map(Tag::getTagName) // Tag 엔티티에서 태그 이름을 가져옴
                .toList();
    }

    private ReviewStatsDTO getReviewStatsDTO(UUID trainerId){
        Double averageRating = reviewRepository.findAverageRatingByTrainerId(trainerId);
        Long reviewCount = reviewRepository.countByReviewedTrainerId(trainerId);

        return new ReviewStatsDTO(
                averageRating != null ? averageRating : 0.0, // 평균 평점 (NULL일 경우 0.0)
                reviewCount != null ? reviewCount : 0L  // 후기 개수 (NULL일 경우 0));
        );
    }


    @Override
    public void applyTrainer(UUID userId, TrainerApplicationRequestDTO applicationReq, List<MultipartFile> certificationFiles) {

        PetUser petUser = findAndValidateUser(userId);

        Trainer trainer = findOrCreateTrainer(userId, petUser);

        trainer.setIntroduction(applicationReq.introduction());
        trainer.setExperienceYears(applicationReq.experienceYears());
        // 자기소개 및 경력은 개선필요

        processCertifications(trainer, applicationReq, certificationFiles);

        trainerRepository.save(trainer);

    }
    private PetUser findAndValidateUser(UUID userId) {
        // PetUserRepository를 사용하여 신청한 userId로 PetUser 엔티티를 조회합니다. (사용자가 없을 경우 예외 처리)
        PetUser petUser = petUserRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다 ID: %s".formatted(userId), HttpStatus.NOT_FOUND));

        //조회된 PetUser의 현재 상태(역할)를 확인하여 이미 훈련사이거나 신청 대기 중이라면 중복 신청 예외를 발생시킵니다.
        if (petUser.getRole() == UserRole.TRAINER || petUser.getRole() == UserRole.ADMIN) {
            throw new DuplicateRequestException("이미 훈련사로 활동 중이거나 관리자입니다.");
        }
        return petUser;
    }
    private Trainer findOrCreateTrainer(UUID userId, PetUser petUser){
        //PetUser에 연결된 Trainer 엔티티가 이미 있는지 조회하고 없으면 생성.
        return trainerRepository.findById(userId) // Trainer ID = User ID (@MapsID)
                .orElseGet(() -> {
                    Trainer newTrainer = new Trainer();
                    newTrainer.setUser(petUser); // PetUser 관계 설정
                    return newTrainer;
                });
    }


    // 3. 자격증 목록 처리
    private void processCertifications(Trainer trainer, TrainerApplicationRequestDTO applicationReq, List<MultipartFile> certificationFiles) {
        List<CertificationRequestDTO> certRequests = applicationReq.certifications();

        // 초기 검증: 자격증 정보 목록이 null이거나 비어있으면 할 일이 없습니다.
        if (certRequests == null || certRequests.isEmpty()) {
            return;
        }
        // 초기 검증: 자격증 정보 목록과 첨부된 파일 목록의 개수 일치 확인
        if (certRequests.size() != certificationFiles.size()) {
            throw new IllegalArgumentException("제출된 자격증 정보 수와 첨부된 파일 수가 일치하지 않습니다.");
        }
        // 각 자격증 정보 DTO와 해당 파일을 순회하며 처리
        for (int i = 0; i < certRequests.size(); i++) {
            CertificationRequestDTO certReqDTO = certRequests.get(i);
            MultipartFile certificationFile = certificationFiles.get(i);
            processSingleCertification(trainer, certReqDTO, certificationFile);
        }
    }

    // 개별 자격증 처리 (파일 업로드, Certification 엔티티 생성 및 저장) 로직을 분리한 메소드
    private void processSingleCertification(Trainer trainer, CertificationRequestDTO certReqDTO, MultipartFile certificationFile) {
        String fileUrl = null;
        if (certificationFile != null && !certificationFile.isEmpty()) {
            try {
                fileUrl = fileUploaderService.uploadFile(certificationFile);
                // 추가 예정
            } catch (IOException e) {
                throw new CustomException("자격증 파일 업로드 중 입출력 오류 발생" + certificationFile.getOriginalFilename(), e , HttpStatus.INTERNAL_SERVER_ERROR);
            } catch (Exception e) {
                throw new CustomException("자격증 파일 업로드 중 알 수 없는 오류 발생" + certificationFile.getOriginalFilename(), e, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
        Certification certification = new Certification();

        certification.setTrainer(trainer);
        certification.setCertName(certReqDTO.certName());
        certification.setIssuingBody(certReqDTO.issuingBody());
        certification.setIssueDate(certReqDTO.issueDate());

        certification.setFileUrl(fileUrl);
        certification.setApproved(false);
        certificationRepository.save(certification);
    }

}
