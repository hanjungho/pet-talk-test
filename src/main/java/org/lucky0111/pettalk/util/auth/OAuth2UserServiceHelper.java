package org.lucky0111.pettalk.util.auth;

import org.lucky0111.pettalk.domain.dto.auth.KakaoResponse;
import org.lucky0111.pettalk.domain.dto.auth.NaverResponse;
import org.lucky0111.pettalk.domain.dto.auth.OAuth2Response;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class OAuth2UserServiceHelper {

    public OAuth2Response getOAuth2Response(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equals("naver")) {
            return new NaverResponse(attributes);
        } else if (registrationId.equals("kakao")) {
            return new KakaoResponse(attributes);
        } else {
            return null;
        }
    }
}