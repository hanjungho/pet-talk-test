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
import org.lucky0111.pettalk.util.auth.AuthServiceHelper;
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
    private final AuthServiceHelper authServiceHelper;

    @Value("${front.url}")
    private String frontUrl;

    /**
     * OAuth2 사용자 정보를 담는 클래스입니다.
     */
    private static class OAuth2UserInfo {
        String provider;
        String providerId;
        String email;
        String name;
        PetUser existingUser;
    }

    /**
     * OAuth2UserInfo를 추출합니다.
     * CustomOAuth2User인 경우, 해당 클래스에서 정보를 추출합니다.
     * 일반 OAuth2User인 경우, OAuth2UserServiceHelper를 통해 정보를 추출합니다.
     */
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

    /**
     * CustomOAuth2User에서 필요한 정보를 추출합니다.
     */
    private void extractFromCustomOAuth2User(CustomOAuth2User customUser, OAuth2UserInfo userInfo) {
        userInfo.provider = customUser.getProvider();
        userInfo.providerId = customUser.getSocialId();
        userInfo.email = extractEmail(customUser);
        userInfo.name = customUser.getName();

        log.debug("CustomOAuth2User에서 정보 추출: provider={}, providerId={}, email={}, name={}",
                userInfo.provider, userInfo.providerId, userInfo.email, userInfo.name);
    }

    /**
     * CustomOAuth2User에서 이메일을 추출합니다.
     * 이메일이 null인 경우, attributes에서 email 키로 값을 가져옵니다.
     */
    private String extractEmail(CustomOAuth2User customUser) {
        String email = customUser.getEmail();
        if (email == null && customUser.getAttributes().containsKey("email")) {
            email = (String) customUser.getAttributes().get("email");
        }
        return email;
    }

    /**
     * 일반 OAuth2 사용자 정보에서 필요한 정보를 추출합니다.
     */
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

    /**
     * 기존 사용자를 찾습니다.
     */
    private void findExistingUser(OAuth2UserInfo userInfo) {
        if (userInfo.provider != null && userInfo.providerId != null) {
            userInfo.existingUser = userRepository.findByProviderAndSocialId(userInfo.provider, userInfo.providerId);
        }
    }

    /**
     * 사용자가 등록된 경우, 토큰을 생성하여 프론트엔드로 리다이렉트합니다.
     */
    private boolean shouldRedirectWithTokens(OAuth2UserInfo userInfo) {
        return userInfo.existingUser != null && userInfo.existingUser.getNickname() != null;
    }

    /**
     * 사용자 정보가 유효한지 검증합니다.
     */
    private boolean validateUserInfo(OAuth2UserInfo userInfo, HttpServletResponse response) throws IOException {
        if (userInfo.provider == null || userInfo.providerId == null) {
            log.error("OAuth2 응답에 필수 정보가 누락되었습니다.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "OAuth2 응답에 필수 정보가 누락되었습니다.");
            return false;
        }
        return true;
    }

    /**
     * 사용자가 등록되지 않은 경우, 임시 인증 토큰을 생성합니다.
     */
    private String createTempToken(OAuth2UserInfo userInfo) {
        return jwtUtil.createTempToken(
                userInfo.provider,
                userInfo.providerId,
                userInfo.email,
                userInfo.name,
                30 * 60 * 1000L // 30분
        );
    }

    /**
     * 사용자가 등록되지 않은 경우, 프론트엔드로 리다이렉트합니다.
     */
    private void redirectToRegister(HttpServletResponse response, String tempToken) throws IOException {
        String targetUrl = frontUrl + "/register?token=" + tempToken;
        log.debug("리다이렉트 주소: {}", targetUrl);
        response.sendRedirect(targetUrl);
    }

    /**
     * 사용자 정보를 기반으로 응답 데이터를 생성합니다.
     */
    private Map<String, Object> createResponseData(TokenDTO tokens, PetUser user) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", tokens.accessToken());
        responseData.put("refreshToken", tokens.refreshToken());
        responseData.put("expiresIn", tokens.expiresIn());
        responseData.put("user", authServiceHelper.createUserDataMap(user));

        return responseData;
    }

    /**
     * Base64로 인코딩된 JSON 문자열을 생성합니다.
     */
    private String encodeResponseData(Map<String, Object> responseData) throws IOException {
        String jsonData = objectMapper.writeValueAsString(responseData);
        byte[] encodedBytes = Base64.getEncoder().encode(jsonData.getBytes(StandardCharsets.UTF_8));
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }

    private String createTargetUrl(String encodedData) throws UnsupportedEncodingException {
        return frontUrl + "/oauth/callback?data=" + URLEncoder.encode(encodedData, StandardCharsets.UTF_8);
    }

    /**
     * OAuth2 로그인 성공 시 호출되는 메서드로, 사용자 정보를 추출하고
     * 기존 사용자인 경우 토큰을 생성하여 프론트엔드로 리다이렉트합니다.
     */
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