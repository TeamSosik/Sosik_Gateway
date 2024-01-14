package com.example.SoSikGateway.config;

import com.example.SoSikGateway.util.JwtTokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private final JwtTokenUtils jwtTokenUtils;

    public AuthorizationHeaderFilter(JwtTokenUtils jwtTokenUtils) {
        super(Config.class);
        this.jwtTokenUtils = jwtTokenUtils;
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            if (UrlCheck(exchange.getRequest().getURI().getPath())) {
                return chain.filter(exchange);
            }


            ServerHttpRequest request = exchange.getRequest();
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) return onError(exchange,
                    "No authorization header", HttpStatus.UNAUTHORIZED);
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("\"","");
            try {
                jwtTokenUtils.validateToken(jwt);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            Object memberId = jwtTokenUtils.parseClaimsJws(jwt).get("memberId");
            exchange.getRequest().mutate().header("memberId", memberId.toString());

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.setComplete();
    }

    private boolean isJwtValid(String jwt) {
        String subject = null;
        try {

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return !Strings.isBlank(subject);
    }

    public static class Config {
    }

    public static boolean UrlCheck(String path) {
        if (path.contains("/members/v1/sign-up") ||
                path.contains("/members/v1/sign-in") ||
                path.contains("/oauth") ||
                path.contains("/members/v1/passwd") ||
                path.contains("/members/v1/sign-out") ||
                path.contains("/members/v1/checkEmail/")){
            return true;
        }
        return false;
    }
}


