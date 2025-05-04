package org.lucky0111.pettalk.service.auth;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface CustomOAuth2UserService extends OAuth2UserService<OAuth2UserRequest, OAuth2User> {
}