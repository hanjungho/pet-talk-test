package org.lucky0111.pettalk.service.auth;

import org.lucky0111.pettalk.domain.dto.auth.TokenDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;

import java.util.Map;

public interface ResponseMapperService {
    /**
     * 토큰 응답 데이터를 생성합니다.
     *
     * @param tokens 토큰 정보
     * @return 토큰 응답 데이터 맵
     */
    Map<String, Object> createTokenResponseData(TokenDTO tokens);

    /**
     * 토큰과 사용자 정보를 포함한 응답 데이터를 생성합니다.
     *
     * @param tokens 토큰 정보
     * @param user   사용자 정보
     * @return 토큰 및 사용자 응답 데이터 맵
     */
    Map<String, Object> createTokenAndUserResponse(TokenDTO tokens, PetUser user);

    /**
     * 닉네임 중복 확인 응답 데이터를 생성합니다.
     *
     * @param isAvailable 사용 가능한지 여부
     * @return 닉네임 중복 확인 응답 데이터 맵
     */
    Map<String, Object> createNicknameCheckResponse(boolean isAvailable);

    /**
     * 닉네임 중복 확인 메시지를 생성합니다.
     *
     * @param isAvailable 사용 가능한지 여부
     * @return 닉네임 중복 확인 메시지
     */
    String createNicknameCheckMessage(boolean isAvailable);

    /**
     * 로그인 응답 데이터를 생성합니다.
     *
     * @param userData 사용자 데이터
     * @return 로그인 응답 데이터 맵
     */
    Map<String, Object> createLoginResponse(Map<String, Object> userData);
}