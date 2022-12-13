package com.example.nrsherr2redisdependdebug

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisOperations
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.session.data.redis.RedisIndexedSessionRepository
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession
import org.springframework.session.security.SpringSessionBackedSessionRegistry


@Configuration
class SecurityConfiguration(private val userDetailsService: UserDetailsService) {
    @Autowired
    private lateinit var sessionRepository: FindByIndexNameSessionRepository<out Session>

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .headers { hdc ->
                hdc.frameOptions { it.sameOrigin() }
                hdc.referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.ORIGIN_WHEN_CROSS_ORIGIN)
            }
            .userDetailsService(userDetailsService())
            .cors().and()
            .csrf { csc ->
                csc.csrfTokenRepository(csrfTokenRepository())
                csc.ignoringRequestMatchers(
                    "/api-public/**",
                    "/public/**",
                    "/login*",
                    "/password/set",
                    "/h2-console/**",
                    "/actuator/**",
                    "/api-secret/**"
                )
                csc.ignoringRequestMatchers(
                    "/api-public/**",
                    "/aca/**",
                    "/aca/fe-return/**",
                    "/login*",
                    "/login",
                    "/password/set",
                    "/public/**",
                    "/h2-console/**"
                )
            }
            .logout { lg ->
                lg.logoutRequestMatcher(AntPathRequestMatcher("/logout"))
                lg.invalidateHttpSession(true)
            }
            .exceptionHandling { e -> e.authenticationEntryPoint(LoginRedirectHandler()) }
            .sessionManagement { ssm ->
                ssm.sessionFixation { it.migrateSession() }
                ssm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .maximumSessions(1).sessionRegistry(sessionRegistry())
            }
            .authorizeHttpRequests { ah ->
                ah.requestMatchers("/v3/api-docs/**", "/v3/api-docs**").permitAll()
                ah.requestMatchers(
                    "/login*",
                    "/login",
                    "/password/set",
                    "/v3/api-docs/**",
                    "/v3/api-docs**",
                    "/swagger-ui**",
                    "/public/**",
                    "/api-public/**",
                    "/ngsw.json*",
                    "/actuator/**",
                    "/ngsw-worker.js*",
                    "/manifest.webmanifest",
                    "/"
                ).permitAll()
                ah.anyRequest().authenticated()
            }
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        return userDetailsService
    }

    @Bean
    fun encoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }



    @Bean
    fun csrfTokenRepository(): HttpSessionCsrfTokenRepository {
        return HttpSessionCsrfTokenRepository().apply {
            setHeaderName("X-XSRF-TOKEN")
            setParameterName("X-XSRF-TOKEN")
            setSessionAttributeName("_csrf")
        }
    }

    @Bean
    fun sessionRegistry(): SessionRegistry {
        return SpringSessionBackedSessionRegistry(sessionRepository)
    }

    class LoginRedirectHandler : LoginUrlAuthenticationEntryPoint("/login") {
        override fun determineUrlToUseForThisRequest(
            request: HttpServletRequest,
            response: HttpServletResponse,
            exception: AuthenticationException?
        ): String {
            return "${this.loginFormUrl}?error=7&requestedUrl=${request.requestURL}"
        }
    }
}

@Configuration
@EnableRedisHttpSession
class SessionConfig(redisConnectionFactory: ObjectProvider<RedisConnectionFactory?>) {
    private val redisConnectionFactory: RedisConnectionFactory?

    init {
        this.redisConnectionFactory = redisConnectionFactory.ifAvailable
    }

    @Bean
    fun sessionRedisOperations(): RedisOperations<String, Any> {
        val redisTemplate = RedisTemplate<String, Any>()
        redisTemplate.setConnectionFactory(redisConnectionFactory!!)
        redisTemplate.keySerializer = StringRedisSerializer()
        redisTemplate.hashKeySerializer = StringRedisSerializer()
        return redisTemplate
    }

    @Bean
    fun redisSessionRepository(sessionRedisOperations: RedisOperations<String?, Any?>?): FindByIndexNameSessionRepository<*> {
        return RedisIndexedSessionRepository(sessionRedisOperations)
    }
}