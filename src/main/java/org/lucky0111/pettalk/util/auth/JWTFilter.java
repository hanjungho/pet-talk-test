package org.lucky0111.pettalk.util.auth;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.user.UserDTO;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Skip filter for refresh token endpoint and other public endpoints
        String path = request.getRequestURI();
        if (path.equals("/api/v1/auth/refresh") ||
                path.equals("/api/v1/auth/check-nickname") ||
                path.equals("/api/v1/auth/register") ||
                path.equals("/") ||
                path.matches("/swagger-ui/.*") ||
                path.matches("/v3/api-docs/.*")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = extractToken(request);

        //Authorization 헤더 검증
        if (authorization == null) {
            System.out.println("token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰
        String token = authorization;

        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Access token expired\",\"code\":\"TOKEN_EXPIRED\"}");
            return;
        }

        //토큰에서 username과 role 획득
        String provider = jwtUtil.getProvider(token);
        String socialId = jwtUtil.getSocialId(token);
        String role = jwtUtil.getRole(token);
        String userId = jwtUtil.getUserId(token);
        String email = jwtUtil.getEmail(token);

        //userDTO를 생성하여 값 set
        UserDTO userDTO = new UserDTO(role, null, provider, socialId, userId, email);

        //UserDetails에 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        // Try to get token from Authorization header first
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // If not in header, check cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}