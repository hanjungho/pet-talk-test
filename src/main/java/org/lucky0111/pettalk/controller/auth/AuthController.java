package org.lucky0111.pettalk.controller.auth;

import org.lucky0111.pettalk.domain.dto.auth.OAuthTempTokenDTO;
import org.lucky0111.pettalk.domain.dto.auth.UserRegistrationDTO;
import org.lucky0111.pettalk.domain.entity.PetUser;
import org.lucky0111.pettalk.repository.user.UserRepository;
import org.lucky0111.pettalk.service.auth.ResponseService;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = {"${front.url}", "http://localhost:3000"}, maxAge = 3600, allowCredentials = "true")
public class AuthController {

    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;
    private final ResponseService responseService;

    public AuthController(JWTUtil jwtUtil, UserRepository userRepository, ResponseService responseService) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.responseService = responseService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO registrationDTO) {
        try {
            // 임시 토큰 검증
            OAuthTempTokenDTO tempTokenInfo = jwtUtil.getTempTokenInfo(registrationDTO.getTempToken());

            if (tempTokenInfo == null) {
                return responseService.createErrorResponse("INVALID_TOKEN", "유효하지 않은 임시 토큰입니다.");
            }

            // 소셜 ID로 이미 존재하는 사용자 확인
            PetUser existingUser = userRepository.findByProviderAndSocialId(
                    tempTokenInfo.getProvider(), tempTokenInfo.getProviderId());

            PetUser petUser;

            if (existingUser != null) {
                // 기존 사용자 정보 업데이트
                petUser = existingUser;
                petUser.setName(registrationDTO.getName());
                petUser.setNickname(registrationDTO.getNickname());
                petUser.setProfileImageUrl(registrationDTO.getProfileImageUrl());

                System.out.println("기존 사용자 정보 업데이트: " + petUser.getUserId() + ", " + petUser.getName());
            } else {
                // 새 사용자 생성
                petUser = new PetUser();
                petUser.setProvider(tempTokenInfo.getProvider());
                petUser.setSocialId(tempTokenInfo.getProviderId());
                petUser.setEmail(tempTokenInfo.getEmail());
                petUser.setName(registrationDTO.getName());
                petUser.setNickname(registrationDTO.getNickname());
                petUser.setProfileImageUrl(registrationDTO.getProfileImageUrl());
                petUser.setRole("ROLE_USER");

                System.out.println("새 사용자 정보 생성: " + petUser.getName() + ", " + petUser.getProvider() + ", " + petUser.getSocialId());
            }

            userRepository.save(petUser);

            // JWT 토큰 발급
            String accessToken = jwtUtil.createJwt(
                    tempTokenInfo.getProvider(),
                    tempTokenInfo.getProviderId(),
                    petUser.getUserId(),
                    "ROLE_USER",
                    60 * 60 * 1000L // 1시간
            );

            // 응답 데이터 생성
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("accessToken", accessToken);
            responseData.put("expiresIn", 3600);

            Map<String, Object> userData = new HashMap<>();
            userData.put("id", petUser.getUserId());
            userData.put("email", petUser.getEmail());
            userData.put("name", petUser.getName());
            userData.put("nickname", petUser.getNickname());
            userData.put("profileImageUrl", petUser.getProfileImageUrl());
            userData.put("role", petUser.getRole());

            responseData.put("user", userData);

            return responseService.createSuccessResponse(responseData, "사용자 등록이 완료되었습니다.");

        } catch (DataIntegrityViolationException e) {
            // 중복 키 또는 무결성 제약 조건 위반 처리
            System.err.println("데이터 무결성 위반 오류: " + e.getMessage());
            return responseService.createErrorResponse("DUPLICATE_DATA", "이미 사용 중인 정보가 포함되어 있습니다. 다른 값을 사용해 주세요.");
        } catch (Exception e) {
            // 기타 예외 처리
            System.err.println("사용자 등록 중 오류 발생: " + e.getMessage());
            e.printStackTrace();
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }

    @GetMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(@RequestParam String nickname) {
        try {
            // 닉네임 중복 확인 로직 구현
            boolean isAvailable = !userRepository.existsByNickname(nickname);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("available", isAvailable);

            return responseService.createSuccessResponse(responseData,
                    isAvailable ? "사용 가능한 닉네임입니다." : "이미 사용 중인 닉네임입니다.");
        } catch (Exception e) {
            System.err.println("닉네임 확인 중 오류 발생: " + e.getMessage());
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }
}