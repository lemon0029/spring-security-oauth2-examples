package io.nullptr

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.DefaultSecurityFilterChain


@Configuration
class SecurityConfig {

    @Value("\${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private lateinit var jwkSetUri: String

    @Bean
    fun securityFilterChain(http: HttpSecurity): DefaultSecurityFilterChain {
        http.authorizeHttpRequests()
            .mvcMatchers(HttpMethod.GET, "/api/resources/**")
            .hasAnyAuthority("SCOPE_resource:read", "SCOPE_resource:write")
            .mvcMatchers(HttpMethod.POST, "/api/resources/**")
            .hasAuthority("SCOPE_resource:write")
            .anyRequest()
            .authenticated()
            .and()
            .oauth2ResourceServer {
                it.jwt()
            }

        return http.build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build()
}