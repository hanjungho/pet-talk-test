package org.lucky0111.pettalk.domain.dto.auth;


import org.lucky0111.pettalk.domain.dto.user.UserDTO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final UserDTO userDTO;

    public CustomOAuth2User(UserDTO userDTO) {

        this.userDTO = userDTO;
    }

    @Override
    public Map<String, Object> getAttributes() {

        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {

                return userDTO.role();
            }
        });

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
