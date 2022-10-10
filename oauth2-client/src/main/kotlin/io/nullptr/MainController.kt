package io.nullptr

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.reactive.function.client.WebClient

@Controller
class MainController {

    @Autowired
    private lateinit var webClient: WebClient

    @GetMapping("/user")
    @ResponseBody
    fun test(@AuthenticationPrincipal oauth2User: OAuth2User) = oauth2User

    @GetMapping("/test-resource-fetch")
    @ResponseBody
    fun test(@RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient): String? {
        return webClient.get()
            .uri("/user/repos")
            .attributes(oauth2AuthorizedClient(authorizedClient))
            .retrieve()
            .bodyToMono(String::class.java)
            .block()
    }

    @GetMapping("/")
    fun index(
        model: Model,
        @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
        @AuthenticationPrincipal oauth2User: OAuth2User
    ): String {

        model.addAttribute("userName", oauth2User.name)
        model.addAttribute("clientName", authorizedClient.clientRegistration.clientName)
        model.addAttribute("userAttributes", oauth2User.attributes)

        return "index"
    }

}