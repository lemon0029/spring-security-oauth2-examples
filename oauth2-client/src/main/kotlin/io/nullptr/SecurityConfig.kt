package io.nullptr

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }

            oauth2Login { }
            formLogin { }
            oauth2Client { }
        }

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder =
        PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun userDetailsService(): UserDetailsService =
        InMemoryUserDetailsManager(
            User("yc", "{noop}pnq123", emptyList()),
            User("nullptr", "{noop}password@123", emptyList()),
            User("ti19", "{noop}123456", emptyList()),
            User(
                "user",
                "{bcrypt}\$2a\$10\$6rwMXarOJdcT30P/4i/pnOSdalwYSVSnZbFoWPW19CbmxmHuwuy16",
                emptyList()
            )
        )

}