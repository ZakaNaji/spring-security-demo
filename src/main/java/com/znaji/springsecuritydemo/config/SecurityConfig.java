package com.znaji.springsecuritydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(request ->
                        request.requestMatchers("/h2-console/**").permitAll()
                                .anyRequest().authenticated())
                .httpBasic(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(DataSource dataSource) {
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}1234")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}1234")
                .roles("ADMIN")
                .build();
        final JdbcUserDetailsManager jdbcUserDetailsService = new JdbcUserDetailsManager();
        jdbcUserDetailsService.setDataSource(dataSource);
        jdbcUserDetailsService.createUser(user1);
        jdbcUserDetailsService.createUser(admin);
        return jdbcUserDetailsService;
    }
}
