package org.lucky0111.pettalk.controller.auth;

import org.lucky0111.pettalk.domain.dto.auth.OAuthTempTokenDTO;
import org.lucky0111.pettalk.domain.dto.auth.UserRegistrationDTO;
import org.lucky0111.pettalk.domain.entity.PetUser;
import org.lucky0111.pettalk.repository.user.UserRepository;
import org.lucky0111.pettalk.service.auth.ResponseService;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
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
        // 임시 토큰 검증
        OAuthTempTokenDTO tempTokenInfo = jwtUtil.getTempTokenInfo(registrationDTO.getTempToken());

        if (tempTokenInfo == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "유효하지 않은 임시 토큰입니다.");
        }

        // 사용자 정보 저장
        PetUser petUser = new PetUser();
        petUser.setProvider(tempTokenInfo.getProvider());
        petUser.setSocialId(tempTokenInfo.getProviderId());
        petUser.setEmail(tempTokenInfo.getEmail());
        petUser.setName(registrationDTO.getName());
        petUser.setNickname(registrationDTO.getNickname());
        petUser.setProfileImageUrl(registrationDTO.getProfileImageUrl());
        petUser.setRole("ROLE_USER");

        userRepository.save(petUser);

        // JWT 토큰 발급
        String accessToken = jwtUtil.createJwt(tempTokenInfo.getProvider(), tempTokenInfo.getProviderId(),petUser.getUserId() , "ROLE_USER", 60 * 60 * 1000L); // 1시간

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
    }

    @GetMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(@RequestParam String nickname) {
        // 닉네임 중복 확인 로직 구현
        boolean isAvailable = true; // 실제로는 DB 조회를 통해 확인

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("available", isAvailable);

        return responseService.createSuccessResponse(responseData,
                isAvailable ? "사용 가능한 닉네임입니다." : "이미 사용 중인 닉네임입니다.");
    }
}