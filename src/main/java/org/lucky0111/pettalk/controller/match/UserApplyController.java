package org.lucky0111.pettalk.controller.match;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.common.ApplyStatus;
import org.lucky0111.pettalk.domain.dto.match.UserApplyRequestDTO;
import org.lucky0111.pettalk.domain.dto.match.UserApplyResponseDTO;
import org.lucky0111.pettalk.service.match.UserApplyService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/match")
@RequiredArgsConstructor
@Tag(name = "매칭 신청", description = "사용자와 트레이너 간의 매칭 신청 관련 API")
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "JWT Bearer token"
)
public class UserApplyController {
    private final UserApplyService userApplyService;
    private static final int PAGE_SIZE = 10;

    @PostMapping
    @Operation(
            summary = "매칭 신청서 제출",
            description = "사용자가 트레이너에게 매칭 신청서를 제출합니다.",
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(responseCode = "201", description = "신청서 생성 성공"),
            }
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<UserApplyResponseDTO> createApply(@RequestBody UserApplyRequestDTO requestDTO) {
        log.info("신청서 제출 요청: trainerId={}", requestDTO.trainerName());
        UserApplyResponseDTO responseDTO = userApplyService.createApply(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseDTO);
    }


    @GetMapping("/user")
    @Operation(
            summary = "사용자 신청 목록 조회",
            description = "로그인한 사용자가 자신이 제출한 매칭 신청 목록을 조회합니다.",
            security = @SecurityRequirement(name = "bearerAuth"),
            parameters = {
                    @Parameter(name = "page", description = "페이지 번호(0부터 시작)", in = ParameterIn.QUERY),
                    @Parameter(name = "applyStatus", description = "상태 필터", in = ParameterIn.QUERY, schema = @Schema(implementation = ApplyStatus.class))
            }
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> getUserApplies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(required = false) ApplyStatus applyStatus) {

        log.info("사용자 신청 목록 조회 요청: page={}, size={}, status={}", page, PAGE_SIZE, applyStatus);

        if (page < 0 || PAGE_SIZE <= 0) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "잘못된 페이지 매개변수입니다."
            ));
        }

        // 페이징 처리 여부에 따라 다른 메서드 호출
        if (page == 0 && PAGE_SIZE >= 100) {
            // 페이징 없이 전체 목록 반환
            List<UserApplyResponseDTO> responseDTOs = applyStatus != null
                    ? userApplyService.getUserAppliesByStatus(applyStatus)
                    : userApplyService.getUserApplies();

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", responseDTOs,
                    "message", "신청 목록을 성공적으로 조회했습니다."
            ));
        } else {
            // 페이징 처리하여 결과 반환
            Pageable pageable = PageRequest.of(page, PAGE_SIZE, Sort.by("createdAt").descending());
            Page<UserApplyResponseDTO> pagedResult = applyStatus != null
                    ? userApplyService.getUserAppliesByStatusPaged(applyStatus, pageable)
                    : userApplyService.getUserAppliesPaged(pageable);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", pagedResult.getContent(),
                    "totalItems", pagedResult.getTotalElements(),
                    "totalPages", pagedResult.getTotalPages(),
                    "currentPage", pagedResult.getNumber(),
                    "message", "신청 목록을 성공적으로 조회했습니다."
            ));
        }
    }

    @GetMapping("/trainer")
    @Operation(
            summary = "트레이너 신청 목록 조회",
            description = "트레이너가 자신에게 접수된 매칭 신청 목록을 조회합니다. 트레이너 또는 관리자 권한이 필요합니다.",
            security = @SecurityRequirement(name = "bearerAuth"),
            parameters = {
                    @Parameter(name = "page", description = "페이지 번호(0부터 시작)", in = ParameterIn.QUERY),
                    @Parameter(name = "applyStatus", description = "상태 필터", in = ParameterIn.QUERY, schema = @Schema(implementation = ApplyStatus.class))
            }
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasAnyAuthority('TRAINER', 'ADMIN')")
    public ResponseEntity<?> getTrainerApplies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(required = false) ApplyStatus applyStatus) {

        log.info("트레이너 신청 목록 조회 요청: page={}, size={}, status={}", page, PAGE_SIZE, applyStatus);

        if (page < 0 || PAGE_SIZE <= 0) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "잘못된 페이지 매개변수입니다."
            ));
        }

        // 페이징 처리 여부에 따라 다른 메서드 호출
        if (page == 0 && PAGE_SIZE >= 100) {
            // 페이징 없이 전체 목록 반환
            List<UserApplyResponseDTO> responseDTOs = applyStatus != null
                    ? userApplyService.getTrainerAppliesByStatus(applyStatus)
                    : userApplyService.getTrainerApplies();

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", responseDTOs,
                    "message", "신청 목록을 성공적으로 조회했습니다."
            ));
        } else {
            // 페이징 처리하여 결과 반환
            Pageable pageable = PageRequest.of(page, PAGE_SIZE, Sort.by("createdAt").descending());
            Page<UserApplyResponseDTO> pagedResult = applyStatus != null
                    ? userApplyService.getTrainerAppliesByStatusPaged(applyStatus, pageable)
                    : userApplyService.getTrainerAppliesPaged(pageable);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", pagedResult.getContent(),
                    "totalItems", pagedResult.getTotalElements(),
                    "totalPages", pagedResult.getTotalPages(),
                    "currentPage", pagedResult.getNumber(),
                    "message", "신청 목록을 성공적으로 조회했습니다."
            ));
        }
    }

    @PatchMapping("/{applyId}/status")
    @Operation(
            summary = "매칭 신청 상태 업데이트",
            description = "트레이너가 매칭 신청의 상태를 업데이트합니다(승인/거절 등). 트레이너 또는 관리자 권한이 필요합니다.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @SecurityRequirement(name = "bearerAuth")
    @PreAuthorize("hasAnyRole('TRAINER', 'ADMIN')")
    public ResponseEntity<?> updateApplyStatus(
            @PathVariable Long applyId,
            @RequestBody ApplyStatus applyStatusRequest) {

        log.info("신청 상태 업데이트 요청: applyId={}, status={}", applyId, applyStatusRequest);

        // 상태 유효성 검사
        ApplyStatus applyStatus;
        try {
            applyStatus = applyStatusRequest;
        } catch (IllegalArgumentException | NullPointerException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "유효하지 않은 상태 값입니다."
            ));
        }

        // 상태 업데이트 서비스 호출
        UserApplyResponseDTO responseDTO = userApplyService.updateApplyStatus(applyId, applyStatus);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", responseDTO,
                "message", "신청 상태가 성공적으로 업데이트되었습니다."
        ));
    }

    @DeleteMapping("/{applyId}/delete")
    @Operation(
            summary = "매칭 신청 삭제",
            description = "사용자가 자신이 제출한 매칭 신청을 삭제합니다.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<?> deleteApply(@PathVariable Long applyId) {
        log.info("신청 삭제 요청: applyId={}", applyId);

        UserApplyResponseDTO responseDTO = userApplyService.deleteApply(applyId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", responseDTO,
                "message", "신청이 성공적으로 삭제되었습니다."
        ));
    }
}