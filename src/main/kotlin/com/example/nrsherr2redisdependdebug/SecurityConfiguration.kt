package com.example.nrsherr2redisdependdebug

import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisOperations
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.web.SecurityFilterChain
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.session.data.redis.RedisIndexedSessionRepository
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession
import org.springframework.session.security.SpringSessionBackedSessionRegistry


@Configuration
class SecurityConfiguration() {
    @Autowired
    private lateinit var sessionRepository: FindByIndexNameSessionRepository<out Session>

    @Bean
    protected fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .sessionManagement()
            .maximumSessions(1)
            .sessionRegistry(sessionRegistry())
        return http.build()
    }

    @Bean
    fun sessionRegistry(): SessionRegistry {
        return SpringSessionBackedSessionRegistry(sessionRepository)
    }
}

//@Configuration
//@EnableRedisHttpSession
//class SessionConfig(redisConnectionFactory: ObjectProvider<RedisConnectionFactory?>) {
//    private val redisConnectionFactory: RedisConnectionFactory?
//
//    init {
//        this.redisConnectionFactory = redisConnectionFactory.ifAvailable
//    }
//
//    @Bean
//    fun sessionRedisOperations(): RedisOperations<String, Any> {
//        val redisTemplate = RedisTemplate<String, Any>()
//        redisTemplate.setConnectionFactory(redisConnectionFactory!!)
//        redisTemplate.keySerializer = StringRedisSerializer()
//        redisTemplate.hashKeySerializer = StringRedisSerializer()
//        return redisTemplate
//    }
//
//    @Bean
//    fun redisSessionRepository(sessionRedisOperations: RedisOperations<String?, Any?>?): FindByIndexNameSessionRepository<*> {
//        return RedisIndexedSessionRepository(sessionRedisOperations)
//    }
//}