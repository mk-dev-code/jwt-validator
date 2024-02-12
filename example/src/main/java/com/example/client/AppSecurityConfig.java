package com.example.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import corp.mkdev.jwt.validator.JwtValidationFilter;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages = { "com.example.client", "corp.mkdev.jwt.validator" })
public class AppSecurityConfig {

    @Autowired
    private JwtValidationFilter jwtValidationFilter;
   
    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        // @formatter:off
        http.authorizeHttpRequests(
                                    (authorize) -> authorize
                                    .requestMatchers("/auth/**").authenticated()                                    
                                    .anyRequest().permitAll()
                                    )
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtValidationFilter,UsernamePasswordAuthenticationFilter.class)        
        ;
        return http.build();
        // @formatter:on
    }
    

}
