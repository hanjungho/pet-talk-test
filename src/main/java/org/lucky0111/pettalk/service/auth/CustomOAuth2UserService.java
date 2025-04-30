package org.lucky0111.pettalk.service.auth;


import org.lucky0111.pettalk.domain.dto.auth.CustomOAuth2User;
import org.lucky0111.pettalk.domain.dto.auth.KakaoResponse;
import org.lucky0111.pettalk.domain.dto.auth.NaverResponse;
import org.lucky0111.pettalk.domain.dto.auth.OAuth2Response;
import org.lucky0111.pettalk.domain.dto.user.UserDTO;
import org.lucky0111.pettalk.domain.entity.PetUser;
import org.lucky0111.pettalk.repository.user.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {

        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if (registrationId.equals("kakao")) {

            oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());
        }
        else {

            return null;
        }
        String provider = oAuth2Response.getProvider();
        String socialId = oAuth2Response.getProviderId();
        PetUser existData = userRepository.findByProviderAndSocialId(provider, socialId);

        if (existData == null) {

            PetUser petUser = new PetUser();
            petUser.setProvider(provider);
            petUser.setSocialId(socialId);
            petUser.setEmail(oAuth2Response.getEmail());
            petUser.setName(oAuth2Response.getName());
            petUser.setRole("ROLE_USER");

            userRepository.save(petUser);

            UserDTO userDTO = new UserDTO("ROLE_USER", oAuth2Response.getName(), provider, socialId);

            return new CustomOAuth2User(userDTO);
        }
        else {

            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());

            userRepository.save(existData);

            UserDTO userDTO = new UserDTO(existData.getRole(), oAuth2Response.getName(), existData.getProvider(), existData.getSocialId());

            return new CustomOAuth2User(userDTO);
        }
    }
}
