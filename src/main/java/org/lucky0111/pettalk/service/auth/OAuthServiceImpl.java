package org.lucky0111.pettalk.service.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.exception.CustomException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthServiceImpl implements OAuthService {

    private final ObjectMapper objectMapper;

    /**
     * OAuth2.0 인증 코드로부터 사용자 정보를 가져옵니다.
     *
     * @param encodedData 인코딩된 데이터
     * @return 디코딩된 JSON 데이터
     */
    @Override
    public String decodeOAuthData(String encodedData) {
        log.debug("Received encoded data: {}", encodedData);
        String urlDecodedData = performUrlDecoding(encodedData);
        return performBase64Decoding(urlDecodedData);
    }

    /**
     * URL 디코딩을 수행합니다.
     *
     * @param encodedData 인코딩된 데이터
     * @return URL 디코딩된 데이터
     */
    private String performUrlDecoding(String encodedData) {
        String urlDecodedData = URLDecoder.decode(encodedData, StandardCharsets.UTF_8);
        urlDecodedData = URLDecoder.decode(urlDecodedData, StandardCharsets.UTF_8);
        log.debug("After URL decoding: {}", urlDecodedData);
        return urlDecodedData;
    }

    /**
     * Base64 디코딩을 수행합니다.
     *
     * @param urlDecodedData URL 디코딩된 데이터
     * @return Base64 디코딩된 JSON 데이터
     */
    private String performBase64Decoding(String urlDecodedData) {
        byte[] decodedBytes = Base64.getDecoder().decode(urlDecodedData);
        String jsonData = new String(decodedBytes, StandardCharsets.UTF_8);
        log.debug("Decoded JSON: {}", jsonData);
        return jsonData;
    }

    /**
     * JSON 데이터를 파싱하여 Map으로 변환합니다.
     *
     * @param jsonData JSON 데이터
     * @return 파싱된 Map
     */
    @SuppressWarnings("unchecked")
    @Override
    public Map<String, Object> parseUserData(String jsonData) {
        try {
            return objectMapper.readValue(jsonData, Map.class);
        } catch (Exception e) {
            throw new CustomException("JSON 파싱 중 오류가 발생했습니다.", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * 사용자 ID를 추출합니다.
     *
     * @param userData 사용자 데이터
     * @return 사용자 UUID
     */
    @SuppressWarnings("unchecked")
    @Override
    public UUID extractUserId(Map<String, Object> userData) {
        Map<String, Object> userInfo = (Map<String, Object>) userData.get("user");
        if (userInfo == null || userInfo.get("id") == null) {
            throw new CustomException("유효하지 않은 사용자 정보입니다.", HttpStatus.BAD_REQUEST);
        }
        return UUID.fromString(userInfo.get("id").toString());
    }
}