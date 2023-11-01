package com.todomypet.apigatewayservice.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;

    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.BAD_REQUEST);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer ", "");

            String subject = getJwtSubject(jwt);
            if (subject == null || subject.isEmpty()) {
                return onError(exchange, "JWT token is Expired", HttpStatus.UNAUTHORIZED);
            }

            request.mutate().header("userId", subject).build();
            exchange.mutate().request(request).build();

            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.setComplete();
    }

    private String getJwtSubject(String jwt) {
        String subject = null;

        try {
            subject = Jwts.parser().setSigningKey(env.getProperty("token.access_token_secret"))
                    .parseClaimsJws(jwt).getBody().getSubject();
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return subject;
    }

    public static class Config {

    }
}
