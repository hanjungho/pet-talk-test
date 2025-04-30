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
import java.util.Iterator;

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

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = authToken.getAuthorizedClientRegistrationId();
        OAuth2Response oAuth2Response = oAuth2UserServiceHelper.getOAuth2Response(registrationId, oAuth2User.getAttributes());

        if (oAuth2Response == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원하지 않는 OAuth2 제공자입니다.");
            return;
        }

        // 임시 토큰 생성
        String tempToken = jwtUtil.createTempToken(
                oAuth2Response.getProvider(),
                oAuth2Response.getProviderId(),
                oAuth2Response.getEmail(),
                oAuth2Response.getName(),
                30 * 60 * 1000L // 30분
        );

        // 프론트엔드로 리다이렉트 (임시 토큰 포함)
        String targetUrl = frontUrl + "/register?token=" + tempToken;
        System.out.println("리다이렉트 주소: " + targetUrl);
        response.sendRedirect(targetUrl);
    }

//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        System.out.println("OAuth2 로그인 성공! 인증 정보: " + authentication);
//
//        //OAuth2User
//        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
//
//        String provider = customUserDetails.getProvider();
//        String socialId = customUserDetails.getSocialId();
//        String userId = customUserDetails.getUserId();
//
//        System.out.println("소셜 이름: " + provider);
//        System.out.println("소셜 아이디: " + socialId);
//        System.out.println("사용자 ID: " + userId);
//
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        String role = auth.getAuthority();
//        System.out.println("사용자 권한: " + role);
//
//        String token = jwtUtil.createJwt(provider, socialId, userId, role, 60*60*60*60L);
//        System.out.println("생성된 JWT 토큰: " + token.substring(0, Math.min(token.length(), 10)) + "...");
//
//        Cookie cookie = createCookie("Authorization", token);
//        System.out.println("쿠키 생성: " + cookie.getName() + ", maxAge: " + cookie.getMaxAge() + ", httpOnly: " + cookie.isHttpOnly());
//
//        response.addCookie(cookie);
//        System.out.println("리다이렉트 주소: " + frontUrl);
//        response.sendRedirect(frontUrl);
//    }
//
//    private Cookie createCookie(String key, String value) {
//        Cookie cookie = new Cookie(key, value);
//        cookie.setMaxAge(60*60*60*60);
//        //cookie.setSecure(true);
//        cookie.setPath("/");
//        cookie.setHttpOnly(true);
//
//        return cookie;
//    }
}