package io.nullptr

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication


@SpringBootApplication
class Oauth2ClientApplication

fun main(args: Array<String>) {
    runApplication<Oauth2ClientApplication>(*args)
}