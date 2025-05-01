package org.lucky0111.pettalk.domain.dto.auth;


import org.lucky0111.pettalk.domain.dto.user.UserDTO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final UserDTO userDTO;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(UserDTO userDTO) {
        this.userDTO = userDTO;
        // 새로운 맵을 생성하여 기본 속성 추가
        this.attributes = new HashMap<>();

        // 기본 속성 추가
        attributes.put("provider", userDTO.provider());
        attributes.put("socialId", userDTO.socialId());
        attributes.put("name", userDTO.name());
        attributes.put("userId", userDTO.userId());
    }

    public CustomOAuth2User(UserDTO userDTO, Map<String, Object> originalAttributes) {
        this.userDTO = userDTO;

        // 원본 속성이 null이면 빈 맵을 생성
        if (originalAttributes == null) {
            this.attributes = new HashMap<>();
        } else {
            // 원본 속성을 새로운 맵에 복사 (불변 맵 문제 해결)
            this.attributes = new HashMap<>(originalAttributes);
        }

        // 기본 속성이 없는 경우 추가
        if (!this.attributes.containsKey("provider")) {
            this.attributes.put("provider", userDTO.provider());
        }
        if (!this.attributes.containsKey("socialId")) {
            this.attributes.put("socialId", userDTO.socialId());
        }
        if (!this.attributes.containsKey("name")) {
            this.attributes.put("name", userDTO.name());
        }
        if (!this.attributes.containsKey("userId")) {
            this.attributes.put("userId", userDTO.userId());
        }
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(() -> userDTO.role());
        return collection;
    }

    @Override
    public String getName() {
        return userDTO.name();
    }

    public String getProvider() {
        return userDTO.provider();
    }

    public String getSocialId() {
        return userDTO.socialId();
    }

    public String getUserId() {
        return userDTO.userId();
    }
}