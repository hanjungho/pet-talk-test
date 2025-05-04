package org.lucky0111.pettalk.config.auth;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    /**
     * Swagger UI 설정
     */
    @Bean
    public OpenAPI openAPI() {
        /*
          Swagger UI에서 사용할 보안 스키마 정의
          JWT 토큰을 Authorization 헤더에 Bearer {token} 형식으로 전달
         */
        SecurityScheme securityScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .in(SecurityScheme.In.HEADER)
                .name("Authorization");

        /*
          Swagger UI에서 사용할 보안 요구 사항 정의
          JWT 토큰을 Authorization 헤더에 Bearer {token} 형식으로 전달
         */
        SecurityRequirement securityRequirement = new SecurityRequirement().addList("bearerAuth");

        return new OpenAPI()
                .components(new Components().addSecuritySchemes("bearerAuth", securityScheme))
                .addSecurityItem(securityRequirement)
                .info(new Info()
                        .title("PetTalk API")
                        .description("PetTalk 애플리케이션의 API 문서")
                        .version("1.0.0"));
    }
}