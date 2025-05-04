package org.lucky0111.pettalk.controller.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.auth.*;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.service.auth.ResponseService;
import org.lucky0111.pettalk.service.user.CommonUserService;
import org.lucky0111.pettalk.service.user.UserService;
import org.lucky0111.pettalk.util.auth.AuthServiceHelper;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.lucky0111.pettalk.util.auth.TokenUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JWTUtil jwtUtil;
    private final PetUserRepository userRepository;
    private final ResponseService responseService;
    private final UserService userService;
    private final ObjectMapper objectMapper;
    private final AuthServiceHelper authHelper;
    private final TokenUtils tokenUtils;
    private final CommonUserService commonUserService;

    // 통합된 에러 처리 메서드
    private ResponseEntity<?> handleUnexpectedError(Exception e, String operation) {
        log.error("{} 중 오류 발생: ", operation, e);
        return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
    }

    // 통합된 토큰 응답 생성 메서드
    private Map<String, Object> createTokenResponseData(TokenDTO tokens) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", tokens.accessToken());
        responseData.put("refreshToken", tokens.refreshToken());
        responseData.put("expiresIn", tokens.expiresIn());
        return responseData;
    }

    private Map<String, Object> createTokenAndUserResponse(TokenDTO tokens, PetUser user) {
        Map<String, Object> responseData = createTokenResponseData(tokens);
        responseData.put("user", authHelper.createUserDataMap(user));
        return responseData;
    }

    private boolean checkNicknameAvailability(String nickname) {
        return !userRepository.existsByNickname(nickname);
    }

    private Map<String, Object> createNicknameCheckResponse(boolean isAvailable) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("available", isAvailable);
        return responseData;
    }

    private String createNicknameCheckMessage(boolean isAvailable) {
        return isAvailable ? "사용 가능한 닉네임입니다." : "이미 사용 중인 닉네임입니다.";
    }

    private OAuthTempTokenDTO validateAndExtractTempToken(String tempToken) {
        OAuthTempTokenDTO tempTokenInfo = jwtUtil.getTempTokenInfo(tempToken);
        if (tempTokenInfo == null) {
            throw new CustomException("유효하지 않은 임시 토큰입니다.", HttpStatus.BAD_REQUEST);
        }
        return tempTokenInfo;
    }

    private PetUser saveUser(PetUser user) {
        return userRepository.save(user);
    }

    private TokenDTO generateTokenPair(PetUser user) {
        return jwtUtil.generateTokenPair(user);
    }

    private String decodeOAuthData(String encodedData) {
        log.debug("Received encoded data: {}", encodedData);

        String urlDecodedData = performUrlDecoding(encodedData);
        String base64DecodedData = performBase64Decoding(urlDecodedData);

        return base64DecodedData;
    }

    private String performUrlDecoding(String encodedData) {
        String urlDecodedData = URLDecoder.decode(encodedData, StandardCharsets.UTF_8);
        urlDecodedData = URLDecoder.decode(urlDecodedData, StandardCharsets.UTF_8);
        log.debug("After URL decoding: {}", urlDecodedData);
        return urlDecodedData;
    }

    private String performBase64Decoding(String urlDecodedData) {
        byte[] decodedBytes = Base64.getDecoder().decode(urlDecodedData);
        String jsonData = new String(decodedBytes, StandardCharsets.UTF_8);
        log.debug("Decoded JSON: {}", jsonData);
        return jsonData;
    }

    private Map<String, Object> parseUserData(String jsonData) {
        try {
            return objectMapper.readValue(jsonData, Map.class);
        } catch (Exception e) {
            throw new CustomException("JSON 파싱 중 오류가 발생했습니다.", HttpStatus.BAD_REQUEST);
        }
    }

    private UUID extractUserId(Map<String, Object> userData) {
        Map<String, Object> userInfo = (Map<String, Object>) userData.get("user");

        if (userInfo == null || userInfo.get("id") == null) {
            throw new CustomException("유효하지 않은 사용자 정보입니다.", HttpStatus.BAD_REQUEST);
        }

        return UUID.fromString(userInfo.get("id").toString());
    }

    private PetUser findAndValidateUser(UUID userId) {
        PetUser user = commonUserService.findUserByIdOrThrow(userId);
        validateUserStatus(user);
        return user;
    }

    private void validateUserStatus(PetUser user) {
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new CustomException("비활성화된 사용자입니다.", HttpStatus.FORBIDDEN);
        }
    }

    private Map<String, Object> createLoginResponse(Map<String, Object> userData) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", getUserDataValue(userData, "accessToken"));
        responseData.put("refreshToken", getUserDataValue(userData, "refreshToken"));
        responseData.put("expiresIn", getUserDataExpiresIn(userData));
        responseData.put("user", userData.get("user"));
        return responseData;
    }

    private String getUserDataValue(Map<String, Object> userData, String key) {
        return (String) userData.get(key);
    }

    private Long getUserDataExpiresIn(Map<String, Object> userData) {
        return ((Number) userData.get("expiresIn")).longValue();
    }

    private String validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new CustomException("리프레시 토큰이 필요합니다.", HttpStatus.BAD_REQUEST);
        }
        return refreshToken;
    }

    private TokenDTO performTokenRefresh(String refreshToken) {
        Optional<TokenDTO> optionalTokenDTO = jwtUtil.refreshAccessToken(refreshToken);

        if (optionalTokenDTO.isPresent()) {
            return optionalTokenDTO.get();
        } else {
            throw new CustomException("유효하지 않은 리프레시 토큰입니다.", HttpStatus.UNAUTHORIZED);
        }
    }

    // Private helper methods
    private PetUser findOrCreateUser(OAuthTempTokenDTO tempTokenInfo, UserRegistrationDTO registrationDTO) {
        // 소셜 ID로 이미 존재하는 사용자 확인
        PetUser existingUser = userRepository.findByProviderAndSocialId(
                tempTokenInfo.provider(), tempTokenInfo.providerId());

        PetUser petUser;

        if (existingUser != null) {
            // 기존 사용자 정보 업데이트
            petUser = existingUser;
            petUser.setName(registrationDTO.name());
            petUser.setNickname(registrationDTO.nickname());
            petUser.setProfileImageUrl(registrationDTO.profileImageUrl());

            log.info("기존 사용자 정보 업데이트: {}, {}", petUser.getUserId(), petUser.getName());
        } else {
            // 새 사용자 생성
            petUser = new PetUser();
            petUser.setProvider(tempTokenInfo.provider());
            petUser.setSocialId(tempTokenInfo.providerId());
            petUser.setEmail(tempTokenInfo.email());
            petUser.setName(registrationDTO.name());
            petUser.setNickname(registrationDTO.nickname());
            petUser.setProfileImageUrl(registrationDTO.profileImageUrl());
            petUser.setRole("USER");
            petUser.setStatus("ACTIVE");

            log.info("새 사용자 정보 생성: {}, {}, {}",
                    petUser.getName(), petUser.getProvider(), petUser.getSocialId());
        }

        return petUser;
    }

    @GetMapping("/user-info")
    public ResponseEntity<?> getUserInfo(HttpServletRequest request) {
        try {
            authHelper.validateAuthentication();

            UUID userId = tokenUtils.getCurrentUserUUID(request);
            PetUser user = commonUserService.findUserByIdOrThrow(userId);

            Map<String, Object> userData = authHelper.createUserDataMap(user);

            return responseService.createSuccessResponse(userData, "사용자 정보를 성공적으로 가져왔습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "사용자 정보 조회");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO registrationDTO) {
        try {
            OAuthTempTokenDTO tempTokenInfo = validateAndExtractTempToken(registrationDTO.tempToken());
            PetUser petUser = findOrCreateUser(tempTokenInfo, registrationDTO);
            petUser = saveUser(petUser);

            TokenDTO tokens = generateTokenPair(petUser);
            Map<String, Object> responseData = createTokenAndUserResponse(tokens, petUser);

            return responseService.createSuccessResponse(responseData, "사용자 등록이 완료되었습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "사용자 등록");
        }
    }

    @GetMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(@RequestParam String nickname) {
        try {
            boolean isAvailable = checkNicknameAvailability(nickname);
            Map<String, Object> responseData = createNicknameCheckResponse(isAvailable);
            String message = createNicknameCheckMessage(isAvailable);

            return responseService.createSuccessResponse(responseData, message);
        } catch (Exception e) {
            return handleUnexpectedError(e, "닉네임 확인");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRequestDTO request) {
        try {
            String refreshToken = validateRefreshToken(request.refreshToken());
            TokenDTO tokenDTO = performTokenRefresh(refreshToken);
            Map<String, Object> responseData = createTokenResponseData(tokenDTO);

            return responseService.createSuccessResponse(responseData, "토큰이 갱신되었습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생: ", e);
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody TokenRequestDTO request) {
        try {
            String refreshToken = request.refreshToken();

            if (refreshToken == null || refreshToken.isBlank()) {
                throw new CustomException("리프레시 토큰이 필요합니다.", HttpStatus.BAD_REQUEST);
            }

            boolean revoked = jwtUtil.revokeRefreshToken(refreshToken);

            if (revoked) {
                return responseService.createSuccessResponse(null, "로그아웃되었습니다.");
            } else {
                throw new CustomException("유효하지 않은 리프레시 토큰입니다.", HttpStatus.UNAUTHORIZED);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("로그아웃 중 오류 발생: ", e);
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }

    @PostMapping("/withdraw")
    public ResponseEntity<?> withdrawUser(HttpServletRequest request) {
        try {
            UUID userId = tokenUtils.getCurrentUserUUID(request);

            // 사용자 탈퇴 처리 서비스 호출
            boolean withdrawn = userService.withdrawUser(userId);

            if (withdrawn) {
                // 모든 리프레시 토큰 폐기
                jwtUtil.revokeAllUserTokens(userId);

                return responseService.createSuccessResponse(null, "계정이 성공적으로 탈퇴 처리되었습니다.");
            } else {
                throw new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("계정 탈퇴 처리 중 오류 발생: ", e);
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(HttpServletRequest request, @RequestBody ProfileUpdateDTO profileUpdateDTO) {
        try {
            UUID userId = tokenUtils.getCurrentUserUUID(request);

            // 닉네임 중복 확인
            if (profileUpdateDTO.nickname() != null && !profileUpdateDTO.nickname().isBlank()) {
                PetUser currentUser = userRepository.findById(userId).orElse(null);
                if (currentUser != null &&
                        !profileUpdateDTO.nickname().equals(currentUser.getNickname()) &&
                        userRepository.existsByNickname(profileUpdateDTO.nickname())) {
                    throw new CustomException("이미 사용 중인 닉네임입니다. 다른 닉네임을 사용해 주세요.", HttpStatus.CONFLICT);
                }
            }

            // 프로필 업데이트 서비스 호출
            PetUser updatedUser = userService.updateProfile(userId, profileUpdateDTO);

            if (updatedUser != null) {
                // 응답 데이터 생성
                Map<String, Object> userData = authHelper.createUserDataMap(updatedUser);
                return responseService.createSuccessResponse(userData, "프로필 정보가 성공적으로 업데이트되었습니다.");
            } else {
                throw new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("프로필 업데이트 중 오류 발생: ", e);
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
        }
    }

    @GetMapping("/token/validate")
    public ResponseEntity<?> validateToken(HttpServletRequest request) {
        try {
            String token = tokenUtils.extractJwtToken(request);

            if (token == null) {
                throw new CustomException("토큰을 찾을 수 없습니다.", HttpStatus.BAD_REQUEST);
            }

            // 토큰 유효성 및 만료 시간 확인
            if (jwtUtil.isExpired(token)) {
                throw new CustomException("토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED);
            }

            // 토큰에서 남은 만료 시간 계산 (초 단위)
            long expiresIn = jwtUtil.getExpiresIn(token);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("valid", true);
            responseData.put("expiresIn", expiresIn);

            return responseService.createSuccessResponse(responseData, "토큰이 유효합니다.");

        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("토큰 검증 중 오류 발생: ", e);
            return responseService.createErrorResponse("INVALID_TOKEN", "유효하지 않은 토큰입니다.");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginWithOAuthData(@RequestBody LoginDTO loginDTO) {
        try {
            String decodedJsonData = decodeOAuthData(loginDTO.encodedData());
            Map<String, Object> userData = parseUserData(decodedJsonData);

            UUID userId = extractUserId(userData);
            PetUser user = findAndValidateUser(userId);

            Map<String, Object> responseData = createLoginResponse(userData);

            return responseService.createSuccessResponse(responseData, "로그인이 성공적으로 처리되었습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            log.error("로그인 처리 중 오류 발생: ", e);
            return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다: " + e.getMessage());
        }
    }
}