package org.lucky0111.pettalk.config.auth;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.auth.OAuth2Response;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.lucky0111.pettalk.util.auth.OAuth2UserServiceHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final OAuth2UserServiceHelper oAuth2UserServiceHelper;

    @Value("${front.url}")
    private String frontUrl;

    public CustomSuccessHandler(JWTUtil jwtUtil, OAuth2UserServiceHelper oAuth2UserServiceHelper) {
        this.jwtUtil = jwtUtil;
        this.oAuth2UserServiceHelper = oAuth2UserServiceHelper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("OAuth2 로그인 성공! 인증 정보: " + authentication);

        // OAuth2User 정보 추출
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = authToken.getPrincipal();

        String registrationId = authToken.getAuthorizedClientRegistrationId();
        String provider = null;
        String providerId = null;
        String email = null;
        String name = null;

        // CustomOAuth2User인 경우
        if (oAuth2User instanceof CustomOAuth2User) {
            CustomOAuth2User customUser = (CustomOAuth2User) oAuth2User;

            provider = customUser.getProvider();
            providerId = customUser.getSocialId();
            email = customUser.getAttributes().containsKey("email") ?
                    (String) customUser.getAttributes().get("email") : null;
            name = customUser.getName();

            System.out.println("CustomOAuth2User에서 정보 추출: provider=" + provider +
                    ", providerId=" + providerId + ", email=" + email + ", name=" + name);
        }
        // 일반 OAuth2User인 경우 - OAuth2UserServiceHelper 사용
        else {
            // 안전하게 맵 복사
            Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());

            // OAuth2 응답 정보 처리
            OAuth2Response oAuth2Response = oAuth2UserServiceHelper.getOAuth2Response(registrationId, attributes);

            if (oAuth2Response == null) {
                System.out.println("OAuth2 응답 생성 실패: 제공자 = " + registrationId);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원하지 않는 OAuth2 제공자입니다.");
                return;
            }

            provider = oAuth2Response.getProvider();
            providerId = oAuth2Response.getProviderId();
            email = oAuth2Response.getEmail();
            name = oAuth2Response.getName();

            System.out.println("OAuth2 사용자 정보: provider=" + provider +
                    ", id=" + providerId +
                    ", email=" + email +
                    ", name=" + name);
        }

        // provider나 providerId가 null이면 오류 반환
        if (provider == null || providerId == null) {
            System.out.println("OAuth2 응답에 필수 정보가 누락되었습니다.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "OAuth2 응답에 필수 정보가 누락되었습니다.");
            return;
        }

        // 임시 토큰 생성
        String tempToken = jwtUtil.createTempToken(
                provider,
                providerId,
                email,
                name,
                30 * 60 * 1000L // 30분
        );

        // 프론트엔드로 리다이렉트 (임시 토큰 포함)
        String targetUrl = frontUrl + "/register?token=" + tempToken;
        System.out.println("리다이렉트 주소: " + targetUrl);
        response.sendRedirect(targetUrl);
    }
}