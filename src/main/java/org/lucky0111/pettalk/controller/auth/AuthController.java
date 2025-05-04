package org.lucky0111.pettalk.controller.auth;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.auth.*;
import org.lucky0111.pettalk.domain.dto.user.ProfileUpdateDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.exception.CustomException;
import org.lucky0111.pettalk.service.auth.OAuthService;
import org.lucky0111.pettalk.service.auth.ResponseMapperService;
import org.lucky0111.pettalk.service.auth.ResponseService;
import org.lucky0111.pettalk.service.user.UserService;
import org.lucky0111.pettalk.util.auth.AuthServiceHelper;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.lucky0111.pettalk.util.auth.TokenUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JWTUtil jwtUtil;
    private final ResponseService responseService;
    private final UserService userService;
    private final ResponseMapperService responseMapper;
    private final OAuthService oAuthService;
    private final TokenUtils tokenUtils;
    private final AuthServiceHelper authHelper;

    /**
     * 사용자 등록
     *
     * @param registrationDTO 사용자 등록 정보
     * @return 사용자 등록 결과
     */
    @Operation(summary = "사용자 등록", description = "OAuth 임시 토큰을 사용하여 사용자를 등록합니다.")
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO registrationDTO) {
        try {
            OAuthTempTokenDTO tempTokenInfo = jwtUtil.getTempTokenInfo(registrationDTO.tempToken());
            if (tempTokenInfo == null) {
                throw new CustomException("유효하지 않은 임시 토큰입니다.", HttpStatus.BAD_REQUEST);
            }

            PetUser petUser = userService.findOrCreateUserFromOAuth(tempTokenInfo, registrationDTO);
            petUser = userService.saveUser(petUser);

            TokenDTO tokens = jwtUtil.generateTokenPair(petUser);
            Map<String, Object> responseData = responseMapper.createTokenAndUserResponse(tokens, petUser);

            return responseService.createSuccessResponse(responseData, "사용자 등록이 완료되었습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "사용자 등록");
        }
    }

    /**
     * 닉네임 중복 확인
     *
     * @param nickname 닉네임
     * @return 닉네임 사용 가능 여부
     */
    @Operation(summary = "닉네임 중복 확인", description = "닉네임 사용 가능 여부를 확인합니다.")
    @GetMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(@RequestParam String nickname) {
        try {
            boolean isAvailable = userService.checkNicknameAvailability(nickname);
            Map<String, Object> responseData = responseMapper.createNicknameCheckResponse(isAvailable);
            String message = responseMapper.createNicknameCheckMessage(isAvailable);

            return responseService.createSuccessResponse(responseData, message);
        } catch (Exception e) {
            return handleUnexpectedError(e, "닉네임 확인");
        }
    }

    /**
     * 사용자 로그인
     *
     * @param request 로그인 정보
     * @return 로그인 결과
     */
    @Operation(summary = "사용자 로그인", description = "OAuth 임시 토큰을 사용하여 사용자를 로그인합니다.")
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRequestDTO request) {
        try {
            if (request.refreshToken() == null || request.refreshToken().isBlank()) {
                throw new CustomException("리프레시 토큰이 필요합니다.", HttpStatus.BAD_REQUEST);
            }

            Optional<TokenDTO> optionalTokenDTO = jwtUtil.refreshAccessToken(request.refreshToken());
            if (optionalTokenDTO.isPresent()) {
                TokenDTO tokenDTO = optionalTokenDTO.get();
                Map<String, Object> responseData = responseMapper.createTokenResponseData(tokenDTO);
                return responseService.createSuccessResponse(responseData, "토큰이 갱신되었습니다.");
            } else {
                throw new CustomException("유효하지 않은 리프레시 토큰입니다.", HttpStatus.UNAUTHORIZED);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "토큰 갱신");
        }
    }

    /**
     * OAuth 로그인
     *
     * @param loginDTO OAuth 로그인 정보
     * @return 로그인 결과
     */
    @Operation(summary = "OAuth 로그인", description = "OAuth 데이터를 사용하여 사용자를 로그인합니다.")
    @PostMapping("/login")
    public ResponseEntity<?> loginWithOAuthData(@RequestBody LoginDTO loginDTO) {
        try {
            String decodedJsonData = oAuthService.decodeOAuthData(loginDTO.encodedData());
            Map<String, Object> userData = oAuthService.parseUserData(decodedJsonData);

            UUID userId = oAuthService.extractUserId(userData);
            PetUser user = userService.findUserByIdOrThrow(userId);
            userService.validateUserStatus(user);

            Map<String, Object> responseData = responseMapper.createLoginResponse(userData);
            return responseService.createSuccessResponse(responseData, "로그인이 성공적으로 처리되었습니다.");
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "로그인 처리");
        }
    }

    /**
     * 사용자 정보 조회
     *
     * @param request HTTP 요청
     * @return 사용자 정보
     */
    @Operation(summary = "사용자 정보 조회", description = "현재 인증된 사용자의 정보를 조회합니다.")
    @GetMapping("/user-info")
    public ResponseEntity<?> getUserInfo(HttpServletRequest request) {
        try {
            UUID userId = tokenUtils.getCurrentUserUUID(request);
            PetUser user = userService.findUserByIdOrThrow(userId);

            return responseService.createSuccessResponse(
                    authHelper.createUserDataMap(user),
                    "사용자 정보를 성공적으로 가져왔습니다."
            );
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "사용자 정보 조회");
        }
    }

    /**
     * 사용자 로그아웃
     *
     * @param request 로그아웃 요청
     * @return 로그아웃 결과
     */
    @Operation(summary = "사용자 로그아웃", description = "현재 인증된 사용자를 로그아웃합니다.")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody TokenRequestDTO request) {
        try {
            if (request.refreshToken() == null || request.refreshToken().isBlank()) {
                throw new CustomException("리프레시 토큰이 필요합니다.", HttpStatus.BAD_REQUEST);
            }

            boolean revoked = jwtUtil.revokeRefreshToken(request.refreshToken());
            if (revoked) {
                return responseService.createSuccessResponse(null, "로그아웃되었습니다.");
            } else {
                throw new CustomException("유효하지 않은 리프레시 토큰입니다.", HttpStatus.UNAUTHORIZED);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "로그아웃");
        }
    }

    /**
     * 사용자 탈퇴
     *
     * @param request HTTP 요청
     * @return 탈퇴 결과
     */
    @Operation(summary = "사용자 탈퇴", description = "현재 인증된 사용자를 탈퇴 처리합니다.")
    @PostMapping("/withdraw")
    public ResponseEntity<?> withdrawUser(HttpServletRequest request) {
        try {
            UUID userId = tokenUtils.getCurrentUserUUID(request);
            boolean withdrawn = userService.withdrawUser(userId);

            if (withdrawn) {
                jwtUtil.revokeAllUserTokens(userId);
                return responseService.createSuccessResponse(null, "계정이 성공적으로 탈퇴 처리되었습니다.");
            } else {
                throw new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "계정 탈퇴 처리");
        }
    }

    /**
     * 사용자 프로필 업데이트
     *
     * @param request            HTTP 요청
     * @param profileUpdateDTO   프로필 업데이트 정보
     * @return 프로필 업데이트 결과
     */
    @Operation(summary = "사용자 프로필 업데이트", description = "현재 인증된 사용자의 프로필 정보를 업데이트합니다.")
    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(HttpServletRequest request, @RequestBody ProfileUpdateDTO profileUpdateDTO) {
        try {
            UUID userId = tokenUtils.getCurrentUserUUID(request);

            // 닉네임 중복 확인
            if (profileUpdateDTO.nickname() != null && !profileUpdateDTO.nickname().isBlank()) {
                PetUser currentUser = userService.findUserById(userId).orElse(null);
                if (currentUser != null &&
                        !profileUpdateDTO.nickname().equals(currentUser.getNickname()) &&
                        !userService.checkNicknameAvailability(profileUpdateDTO.nickname())) {
                    throw new CustomException("이미 사용 중인 닉네임입니다. 다른 닉네임을 사용해 주세요.", HttpStatus.CONFLICT);
                }
            }

            PetUser updatedUser = userService.updateProfile(userId, profileUpdateDTO);
            if (updatedUser != null) {
                return responseService.createSuccessResponse(
                        authHelper.createUserDataMap(updatedUser),
                        "프로필 정보가 성공적으로 업데이트되었습니다."
                );
            } else {
                throw new CustomException("사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND);
            }
        } catch (CustomException e) {
            return responseService.createErrorResponse(e.getHttpStatus().name(), e.getMessage());
        } catch (Exception e) {
            return handleUnexpectedError(e, "프로필 업데이트");
        }
    }

    /**
     * 토큰 검증
     *
     * @param request HTTP 요청
     * @return 토큰 검증 결과
     */
    @Operation(summary = "토큰 검증", description = "현재 인증된 사용자의 토큰을 검증합니다.")
    @GetMapping("/token/validate")
    public ResponseEntity<?> validateToken(HttpServletRequest request) {
        try {
            String token = tokenUtils.extractJwtToken(request);
            if (token == null) {
                throw new CustomException("토큰을 찾을 수 없습니다.", HttpStatus.BAD_REQUEST);
            }

            if (jwtUtil.isExpired(token)) {
                throw new CustomException("토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED);
            }

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

    /**
     * 예외 처리
     *
     * @param e        발생한 예외
     * @param operation 수행 중인 작업
     * @return 오류 응답
     */
    private ResponseEntity<?> handleUnexpectedError(Exception e, String operation) {
        log.error("{} 중 오류 발생: ", operation, e);
        return responseService.createErrorResponse("SERVER_ERROR", "서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
    }
}