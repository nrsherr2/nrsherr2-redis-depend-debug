package com.example.nrsherr2redisdependdebug

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession

@SpringBootApplication
class Nrsherr2RedisDependDebugApplication

fun main(args: Array<String>) {
	runApplication<Nrsherr2RedisDependDebugApplication>(*args)
}

@Configuration
@EnableScheduling
@EnableAsync
class DataConfiguration