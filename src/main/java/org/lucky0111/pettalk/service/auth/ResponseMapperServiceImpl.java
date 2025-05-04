package org.lucky0111.pettalk.service.auth;

import lombok.RequiredArgsConstructor;
import org.lucky0111.pettalk.domain.dto.auth.TokenDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.util.auth.AuthServiceHelper;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class ResponseMapperServiceImpl implements ResponseMapperService {

    private final AuthServiceHelper authHelper;

    /**
     * 토큰 응답 데이터를 생성합니다.
     *
     * @param tokens 토큰 정보
     * @return 토큰 응답 데이터 맵
     */
    @Override
    public Map<String, Object> createTokenResponseData(TokenDTO tokens) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", tokens.accessToken());
        responseData.put("refreshToken", tokens.refreshToken());
        responseData.put("expiresIn", tokens.expiresIn());
        return responseData;
    }

    /**
     * 토큰과 사용자 정보를 포함한 응답 데이터를 생성합니다.
     *
     * @param tokens 토큰 정보
     * @param user   사용자 정보
     * @return 토큰 및 사용자 응답 데이터 맵
     */
    @Override
    public Map<String, Object> createTokenAndUserResponse(TokenDTO tokens, PetUser user) {
        Map<String, Object> responseData = createTokenResponseData(tokens);
        responseData.put("user", authHelper.createUserDataMap(user));
        return responseData;
    }

    /**
     * 닉네임 중복 확인 응답 데이터를 생성합니다.
     *
     * @param isAvailable 사용 가능한지 여부
     * @return 닉네임 중복 확인 응답 데이터 맵
     */
    @Override
    public Map<String, Object> createNicknameCheckResponse(boolean isAvailable) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("available", isAvailable);
        return responseData;
    }

    /**
     * 닉네임 중복 확인 메시지를 생성합니다.
     *
     * @param isAvailable 사용 가능한지 여부
     * @return 닉네임 중복 확인 메시지
     */
    @Override
    public String createNicknameCheckMessage(boolean isAvailable) {
        return isAvailable ? "사용 가능한 닉네임입니다." : "이미 사용 중인 닉네임입니다.";
    }

    /**
     * 로그인 응답 데이터를 생성합니다.
     *
     * @param userData 사용자 데이터
     * @return 로그인 응답 데이터 맵
     */
    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> createLoginResponse(Map<String, Object> userData) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", (String) userData.get("accessToken"));
        responseData.put("refreshToken", (String) userData.get("refreshToken"));
        responseData.put("expiresIn", ((Number) userData.get("expiresIn")).longValue());
        responseData.put("user", userData.get("user"));
        return responseData;
    }
}