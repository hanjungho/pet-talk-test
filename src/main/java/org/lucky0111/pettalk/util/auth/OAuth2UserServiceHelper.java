package org.lucky0111.pettalk.util.auth;

import org.lucky0111.pettalk.domain.dto.auth.KakaoResponse;
import org.lucky0111.pettalk.domain.dto.auth.NaverResponse;
import org.lucky0111.pettalk.domain.dto.auth.OAuth2Response;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class OAuth2UserServiceHelper {

    public OAuth2Response getOAuth2Response(String registrationId, Map<String, Object> attributes) {
        if (attributes == null) {
            System.err.println("OAuth2 attributes is null for provider: " + registrationId);
            return null;
        }

        System.out.println("Processing OAuth2 response for provider: " + registrationId);
        System.out.println("Attributes: " + attributes);

        try {
            if ("naver".equals(registrationId)) {
                return new NaverResponse(attributes);
            } else if ("kakao".equals(registrationId)) {
                return new KakaoResponse(attributes);
            } else {
                System.err.println("Unsupported OAuth2 provider: " + registrationId);
                return null;
            }
        } catch (Exception e) {
            System.err.println("Error creating OAuth2Response for provider " + registrationId + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}