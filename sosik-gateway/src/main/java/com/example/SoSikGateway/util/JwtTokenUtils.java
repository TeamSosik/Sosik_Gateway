package com.example.SoSikGateway.util;


import com.example.SoSikGateway.exception.ApplicationException;
import com.example.SoSikGateway.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
@Slf4j
public class JwtTokenUtils {
    private final Key key;
    private final String secretKey;
    private final Long accessTokenValidityInSeconds;
    private final Long refreshTokenValidityInSeconds;

    public JwtTokenUtils(@Value("${jwt.secret-key}") final String secretKey,
                         @Value("#{T(Long).parseLong('${jwt.access-token-validity-in-seconds}')}") final Long accessTokenValidityInSeconds,
                         @Value("#{T(Long).parseLong('${jwt.refresh-token-validity-in-seconds}')}") final Long refreshTokenValidityInSeconds
                         ) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.secretKey = secretKey;
        this.accessTokenValidityInSeconds = accessTokenValidityInSeconds;
        this.refreshTokenValidityInSeconds = refreshTokenValidityInSeconds;
    }

    // 유저 정보를 가지고 AccessToken, RefreshToken 을 생성하는 메서드
    // Access Token 생성.
    public String createAccessToken(String email, String role,Long memberId) {
        return this.createToken(email, role, accessTokenValidityInSeconds,memberId);
    }

    public String createRefreshToken(String email, String role, Long memberId) {
        return this.createToken(email, role, refreshTokenValidityInSeconds, memberId);
    }

    // Create token
    public String createToken(String email, String roles, long tokenValid,Long memberId) {
        Claims claims = Jwts.claims().setSubject(email); // claims 생성 및 payload 설정
        claims.put("auth", roles); // 권한 설정, key/ value 쌍으로 저장
        claims.put("memberId",memberId);

        Date date = new Date();
        return Jwts.builder()
                .setClaims(claims) // 발행 유저 정보 저장
                .setIssuedAt(date) // 발행 시간 저장
                .setExpiration(new Date(date.getTime() + tokenValid)) // 토큰 유효 시간 저장
                .signWith(SignatureAlgorithm.HS256, createKey()) // 해싱 알고리즘 및 키 설정
                .compact(); // 생성
    }

    private SecretKey createKey() {
        final byte[] secretKeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(secretKeyBytes);
    }

    public Claims parseClaimsJws(final String token) {

        final SecretKey signingKey = createKey();
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public String getUserEmail(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }



    // 어세스 토큰 헤더 설정
    public void setHeaderAccessToken(HttpServletResponse response, String accessToken) {
        response.setHeader("authorization", "bearer "+ accessToken);
    }

    // 리프레시 토큰 헤더 설정
    public void setHeaderRefreshToken(HttpServletResponse response, String refreshToken) {
        response.setHeader("refreshToken", "bearer "+ refreshToken);
    }

    public String resolveAccessToken(HttpServletRequest request) {
        if(request.getHeader("authorization") != null )
            return request.getHeader("authorization").substring(7);
        return null;
    }
    // Request의 Header에서 RefreshToken 값을 가져옵니다. "authorization" : "token'
    public String resolveRefreshToken(HttpServletRequest request) {
        if(request.getHeader("refreshToken") != null )
            return request.getHeader("refreshToken").substring(7);
        return null;
    }


    public boolean validateToken(String token) {
        try {
            parseClaimsJws(token);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token");
            log.trace("Invalid JWT token trace = {}", e);
            throw new ApplicationException(ErrorCode.MALFORMED_TOKEN_ERROR);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token");
            log.trace("Expired JWT token trace = {}", e);
            throw new ApplicationException(ErrorCode.EXPIRED_TOKEN_ERROR);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token");
            log.trace("Unsupported JWT token trace = {}", e);
            throw new ApplicationException(ErrorCode.UNSUPPORTED_TOKEN_ERROR);
        }
        return true;
    }



}
