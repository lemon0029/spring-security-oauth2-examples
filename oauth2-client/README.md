# OAuth2 Login & Client

接入第三方登录所使用的模块是 `spring-security-oauth2-client`，其提供了对 OAuth2 Authorization Code Grant 的支持，而这个模块同时提供了 oauth2-login 和 oauth2-client 两套配置。其中 oauth2-login 配置后会直接生成一个第三方登录的页面，并读取配置渲染在其中，而 oauth2-client 相关配置的作用不是很明显。

```kotlin
dependencies {
	implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
	implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
	implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity5")
	implementation("org.springframework:spring-webflux")
	implementation("io.projectreactor.netty:reactor-netty")
}
```

首先在 application.yml 中添加第三方登录的配置，最终这些配置都会被渲染在登录页面中，默认的 redirect-uri = `{baseUrl}/{action}/oauth2/code/{registrationId}`，会由 OAuth2AuthenticationFilter 来处理（通过 code 获取 access_token 和 user_info）。

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: ${random.uuid}
            client-secret: ${random.uuid}
            scope: read:user,public_rep
          oauth2-client:
            provider: spring-security-oauth2
            client-id: oauth2-client
            client-name: spring-security-oauth2
            client-secret: ${random.uuid}
            client-authentication-method: client_secret_post
            authorization-grant-type: authorization_code
            redirect-uri: http://127.0.0.1:8080/login/oauth2/code/oauth2-client
            scope: user:read
        provider:
          spring-security-oauth2:
            authorization-uri: http://172.21.110.93:9000/oauth2/authorize
            token-uri: http://172.21.110.93:9000/oauth2/token
            jwk-set-uri: http://172.21.110.93:9000/oauth2/jwks
            user-info-uri: http://172.21.110.93:8000/user
            user-name-attribute: user_name
```

另外不需要任何的多余配置，直接开启应用打开 http://127.0.0.1:8080/login 即可进入到登录页面，并且应用的所有接口都需要认证过才能访问，这里添加了 SecurityFilterChain 来覆盖自动配置：

```kotlin
@Bean
fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http {
        authorizeRequests {
            authorize(anyRequest, authenticated)
        }

        oauth2Login { }
    }

    return http.build()
}
```

