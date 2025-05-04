package org.lucky0111.pettalk.config.auth;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.auth.OAuth2Response;

import org.lucky0111.pettalk.domain.dto.auth.TokenDTO;
import org.lucky0111.pettalk.domain.entity.user.PetUser;
import org.lucky0111.pettalk.repository.user.PetUserRepository;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.lucky0111.pettalk.util.auth.OAuth2UserServiceHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final OAuth2UserServiceHelper oAuth2UserServiceHelper;
    private final PetUserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Value("${front.url}")
    private String frontUrl;

    private static class OAuth2UserInfo {
        String provider;
        String providerId;
        String email;
        String name;
        PetUser existingUser;
    }

    private OAuth2UserInfo extractOAuth2UserInfo(Authentication authentication) {
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = authToken.getPrincipal();
        String registrationId = authToken.getAuthorizedClientRegistrationId();

        OAuth2UserInfo userInfo = new OAuth2UserInfo();

        if (oAuth2User instanceof CustomOAuth2User) {
            extractFromCustomOAuth2User((CustomOAuth2User) oAuth2User, userInfo);
        } else {
            extractFromGeneralOAuth2User(oAuth2User, registrationId, userInfo);
        }

        findExistingUser(userInfo);
        return userInfo;
    }

    private void extractFromCustomOAuth2User(CustomOAuth2User customUser, OAuth2UserInfo userInfo) {
        userInfo.provider = customUser.getProvider();
        userInfo.providerId = customUser.getSocialId();
        userInfo.email = extractEmail(customUser);
        userInfo.name = customUser.getName();

        log.debug("CustomOAuth2User에서 정보 추출: provider={}, providerId={}, email={}, name={}",
                userInfo.provider, userInfo.providerId, userInfo.email, userInfo.name);
    }

    private String extractEmail(CustomOAuth2User customUser) {
        String email = customUser.getEmail();
        if (email == null && customUser.getAttributes().containsKey("email")) {
            email = (String) customUser.getAttributes().get("email");
        }
        return email;
    }

    private void extractFromGeneralOAuth2User(OAuth2User oAuth2User, String registrationId, OAuth2UserInfo userInfo) {
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        OAuth2Response oAuth2Response = oAuth2UserServiceHelper.getOAuth2Response(registrationId, attributes);

        if (oAuth2Response != null) {
            userInfo.provider = oAuth2Response.getProvider();
            userInfo.providerId = oAuth2Response.getProviderId();
            userInfo.email = oAuth2Response.getEmail();
            userInfo.name = oAuth2Response.getName();

            log.debug("OAuth2 사용자 정보: provider={}, id={}, email={}, name={}",
                    userInfo.provider, userInfo.providerId, userInfo.email, userInfo.name);
        }
    }

    private void findExistingUser(OAuth2UserInfo userInfo) {
        if (userInfo.provider != null && userInfo.providerId != null) {
            userInfo.existingUser = userRepository.findByProviderAndSocialId(userInfo.provider, userInfo.providerId);
        }
    }

    private boolean shouldRedirectWithTokens(OAuth2UserInfo userInfo) {
        return userInfo.existingUser != null && userInfo.existingUser.getNickname() != null;
    }

    private boolean validateUserInfo(OAuth2UserInfo userInfo, HttpServletResponse response) throws IOException {
        if (userInfo.provider == null || userInfo.providerId == null) {
            log.error("OAuth2 응답에 필수 정보가 누락되었습니다.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "OAuth2 응답에 필수 정보가 누락되었습니다.");
            return false;
        }
        return true;
    }

    private String createTempToken(OAuth2UserInfo userInfo) {
        return jwtUtil.createTempToken(
                userInfo.provider,
                userInfo.providerId,
                userInfo.email,
                userInfo.name,
                30 * 60 * 1000L // 30분
        );
    }

    private void redirectToRegister(HttpServletResponse response, String tempToken) throws IOException {
        String targetUrl = frontUrl + "/register?token=" + tempToken;
        log.debug("리다이렉트 주소: {}", targetUrl);
        response.sendRedirect(targetUrl);
    }

    private Map<String, Object> createResponseData(TokenDTO tokens, PetUser user) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", tokens.accessToken());
        responseData.put("refreshToken", tokens.refreshToken());
        responseData.put("expiresIn", tokens.expiresIn());
        responseData.put("user", createUserDataMap(user));

        return responseData;
    }

    private Map<String, Object> createUserDataMap(PetUser user) {
        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getUserId());
        userData.put("email", user.getEmail());
        userData.put("name", user.getName());
        userData.put("nickname", user.getNickname());
        userData.put("profileImageUrl", user.getProfileImageUrl());
        userData.put("role", user.getRole());

        return userData;
    }

    private String encodeResponseData(Map<String, Object> responseData) throws IOException {
        String jsonData = objectMapper.writeValueAsString(responseData);
        byte[] encodedBytes = Base64.getEncoder().encode(jsonData.getBytes(StandardCharsets.UTF_8));
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }

    private String createTargetUrl(String encodedData) throws UnsupportedEncodingException {
        return frontUrl + "/oauth/callback?data=" + URLEncoder.encode(encodedData, StandardCharsets.UTF_8);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 로그인 성공! 인증 정보: {}", authentication);

        OAuth2UserInfo userInfo = extractOAuth2UserInfo(authentication);

        if (shouldRedirectWithTokens(userInfo)) {
            redirectWithTokens(response, userInfo.existingUser);
            return;
        }

        if (!validateUserInfo(userInfo, response)) {
            return;
        }

        String tempToken = createTempToken(userInfo);
        redirectToRegister(response, tempToken);
    }

    /**
     * 사용자 인증 성공 후 토큰을 생성하고 프론트엔드로 리다이렉트합니다.
     */
    private void redirectWithTokens(HttpServletResponse response, PetUser user) throws IOException {
        TokenDTO tokens = jwtUtil.generateTokenPair(user);
        Map<String, Object> responseData = createResponseData(tokens, user);
        String encodedData = encodeResponseData(responseData);
        String targetUrl = createTargetUrl(encodedData);

        response.sendRedirect(targetUrl);
    }
}