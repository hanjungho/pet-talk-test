package org.lucky0111.pettalk.domain.dto.auth;

import java.util.Map;

public class NaverResponse implements OAuth2Response {

    private final Map<String, Object> attribute;

    public NaverResponse(Map<String, Object> attributes) {
        if (attributes.containsKey("response") && attributes.get("response") instanceof Map) {
            this.attribute = (Map<String, Object>) attributes.get("response");
        } else {
            // Naver의 응답 형식이 예상과 다른 경우 처리
            System.err.println("Unexpected Naver response format: " + attributes);
            this.attribute = null;
        }
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return attribute != null && attribute.containsKey("id") ?
                attribute.get("id").toString() : null;
    }

    @Override
    public String getEmail() {
        return attribute != null && attribute.containsKey("email") ?
                attribute.get("email").toString() : null;
    }

    @Override
    public String getName() {
        return attribute != null && attribute.containsKey("name") ?
                attribute.get("name").toString() :
                "NaverUser_" + (getProviderId() != null ? getProviderId().substring(0, 6) : "unknown");
    }
}
