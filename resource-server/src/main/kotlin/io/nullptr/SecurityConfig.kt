package io.nullptr

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.DefaultSecurityFilterChain


@Configuration
class SecurityConfig {

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
}