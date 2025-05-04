package org.lucky0111.pettalk.service.auth;

import java.util.Map;
import java.util.UUID;

public interface OAuthService {
    /**
     * OAuth2.0 인증 코드로부터 사용자 정보를 가져옵니다.
     *
     * @param encodedData 인코딩된 데이터
     * @return 디코딩된 JSON 데이터
     */
    String decodeOAuthData(String encodedData);

    /**
     * JSON 데이터를 파싱하여 Map으로 변환합니다.
     *
     * @param jsonData JSON 데이터
     * @return 파싱된 Map
     */
    Map<String, Object> parseUserData(String jsonData);

    /**
     * 사용자 ID를 추출합니다.
     *
     * @param userData 사용자 데이터
     * @return 사용자 UUID
     */
    UUID extractUserId(Map<String, Object> userData);
}
