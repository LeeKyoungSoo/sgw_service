package com.lnworks.sgw_service.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Objects;

@Component
@Slf4j
public class CustomAuthFilter extends AbstractGatewayFilterFactory<CustomAuthFilter.Config> {
    @Autowired
    private Environment env;

    public CustomAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if ( !request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Not found authorization header!", HttpStatus.UNAUTHORIZED);
            }

            String userId = request.getHeaders().get("userId").get(0);
            String authorization
                    = Objects.requireNonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
            String token = authorization.replace("Bearer", "").trim();
            if (!isJwtValid(token, userId)) {
                return onError(exchange, "JWT token is not vaild.", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange); // 토큰이 일치할 때
        });
    }
    private Mono<Void> onError(ServerWebExchange exchange, String e, HttpStatus status) {
        ServerHttpResponse res = exchange.getResponse();
        res.setStatusCode(status);
        log.error(e);
        return  res.setComplete();
    }

    private boolean isJwtValid(String token, String userId) {
        boolean isValid = true;
        String subject = null;

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(env.getProperty("token.secret").getBytes()).build()
                    .parseClaimsJws(token)
                    .getBody();
            subject = (String) claims.get("corin_id"); //organizationId를 가져옴.
        } catch (Exception ex) {
            isValid = false;
            log.info("Exception : " + ex);
        }

        if ( subject == null || subject.isEmpty() || !subject.equals(userId) ) isValid = false;

        //만료시간 체크 필요

        return isValid;
    }

    public static class Config {

    }
}