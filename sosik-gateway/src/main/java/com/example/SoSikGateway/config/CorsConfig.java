package com.example.SoSikGateway.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOriginPattern("http://localhost:3000");
        config.addAllowedHeader(""); //특정 header만 허용
        config.addAllowedMethod(""); //특정 메소드만 허용
        config.addExposedHeader("Authorization");
        source.registerCorsConfiguration("/**", config); //corsConfiguration으로 등록
        return new CorsFilter(source);
    }
}