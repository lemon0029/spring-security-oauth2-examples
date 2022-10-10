# Resource Server



资源服务器的意义在于存储业务数据和提供对应的接口给其它应用调用，需要先通过授权服务器拿到 access_token 才可访问，其通过校验每个请求的 Authorization 头来判断当前是否是已认证状态，并使用授权服务器提供的加密算法和密钥来校验这个令牌的有效性。

在 Spring Security 中搭建资源服务器很简单，只需要引入依赖：

```kotlin
implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
```

然后在配置中设置 jwk-set-uri 的值：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:9000/oauth2/jwks
```

最后配置过滤链即可，这个配置是建立在令牌是 JWT 格式的，负载中会存在令牌的权限，默认解析到 Authentication 对象之后会添加 `SCOPE_` 的前缀。

```kotlin
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
```

