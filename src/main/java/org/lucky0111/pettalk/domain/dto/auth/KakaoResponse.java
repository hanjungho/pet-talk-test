package org.lucky0111.pettalk.domain.dto.auth;

import java.util.Map;

public class KakaoResponse implements OAuth2Response {

    private final Map<String, Object> attributes;
    private final Map<String, Object> properties;
    private final Map<String, Object> kakao_account;

    public KakaoResponse(Map<String, Object> attributes) {
        this.attributes = attributes;
        this.properties = attributes.containsKey("properties") ?
                (Map<String, Object>) attributes.get("properties") : null;
        this.kakao_account = attributes.containsKey("kakao_account") ?
                (Map<String, Object>) attributes.get("kakao_account") : null;
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getEmail() {
        // kakao_account에서 이메일 정보를 가져옵니다
        return (kakao_account != null && kakao_account.containsKey("email")) ?
                kakao_account.get("email").toString() : null;
    }

    @Override
    public String getName() {
        // properties에서 nickname 정보를 가져옵니다
        return (properties != null && properties.containsKey("nickname")) ?
                properties.get("nickname").toString() :
                "KakaoUser_" + getProviderId().substring(0, 6);
    }
}