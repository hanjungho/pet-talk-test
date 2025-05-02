package org.lucky0111.pettalk.config.auth;


import jakarta.servlet.http.HttpServletRequest;
import org.lucky0111.pettalk.service.auth.CustomOAuth2UserService;
import org.lucky0111.pettalk.util.auth.JWTFilter;
import org.lucky0111.pettalk.util.auth.JWTUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    @Value("${front.url}")
    private String fronturl;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler, JWTUtil jwtUtil) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        // 개발 환경을 위해 모든 오리진 허용 (프로덕션에서는 변경 필요)
                        configuration.addAllowedOrigin("*");

                        // 또는 특정 오리진만 허용하려면 아래 코드 사용
                        // List<String> allowedOrigins = Arrays.asList(fronturl, "http://localhost:8443");
                        // configuration.setAllowedOrigins(allowedOrigins);

                        // 모든 HTTP 메서드 허용
                        configuration.setAllowedMethods(
                                Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
                        );

                        // 모든 오리진을 허용할 때는 credentials를 false로 설정
                        configuration.setAllowCredentials(false);

                        // 특정 오리진만 허용할 때는 credentials를 true로 설정 가능
                        // configuration.setAllowCredentials(true);

                        // 허용할 헤더 설정
                        configuration.setAllowedHeaders(
                                Arrays.asList("Authorization", "Content-Type", "Accept", "X-Requested-With")
                        );

                        // 브라우저에 노출할 헤더 설정
                        configuration.setExposedHeaders(
                                Arrays.asList("Authorization", "Set-Cookie")
                        );

                        // preflight 요청 캐시 시간 설정 (초 단위)
                        configuration.setMaxAge(3600L);

                        return configuration;
                    }
                }))

                // CSRF 보호 비활성화
                .csrf((auth) -> auth.disable())

                // 폼 로그인 방식 비활성화
                .formLogin((auth) -> auth.disable())

                // HTTP Basic 인증 방식 비활성화
                .httpBasic((auth) -> auth.disable())

                // JWT 필터 추가
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)

                // OAuth2 로그인 설정
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler)
                )

                // 경로별 인가 설정
                .authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/api/v1/auth/register",
//                                "/api/v1/auth/check-nickname", "/api/v1/auth/refresh", "/").permitAll()
//                        .requestMatchers("/api/v1/auth/user-info", "/api/v1/auth/logout",
//                                "/api/v1/auth/withdraw", "/api/v1/auth/profile",
//                                "/api/v1/auth/token/validate").authenticated()
                        .requestMatchers("/**").permitAll()
                        .anyRequest().authenticated())

                // 세션 관리 설정: STATELESS
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}