package com.todomypet.apigatewayservice.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Component
@Slf4j
public class CheckAdminFilter extends AbstractGatewayFilterFactory<CheckAdminFilter.Config>  {

    Environment env;

    public CheckAdminFilter(Environment env) {
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

            String authorization = getAuthorizationFromJwt(jwt);
            if (!authorization.equals("ROLE_ADMIN")) {
                return onError(exchange, "Don't have admin permissions.", HttpStatus.FORBIDDEN);
            }

            log.info(">>> permit admin account: " + LocalDateTime.now());

            exchange.mutate().request(request).build();

            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = response.bufferFactory().wrap(err.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private String getAuthorizationFromJwt(String jwt) {
        log.info(">>> admin 권한 확인");
        String authorization = null;
        try {
            authorization = Jwts.parser().setSigningKey(env.getProperty("token.access_token_secret"))
                    .parseClaimsJws(jwt).getBody().get("auth").toString();
        } catch (ExpiredJwtException e) {
            log.error(">>> Expired JWT token.");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return authorization;
    }

    public static class Config {

    }
}
