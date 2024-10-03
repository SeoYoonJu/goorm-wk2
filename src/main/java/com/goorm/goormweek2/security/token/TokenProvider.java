package com.goorm.goormweek2.security.token;

import static java.lang.System.getenv;

import com.goorm.goormweek2.member.MemberRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenProvider {

    Map<String, String> env = getenv();
    private String secretKey = Base64.getEncoder().encodeToString(
        Objects.requireNonNull(env.get("JWT_SECRET")).getBytes());
    private final MemberRepository memberRepository;
    private static final String AUTHORITIES_KEY = "ROLE_USER";

    public TokenDTO generateToken(Authentication authentication) {
        long expirationTime = 1000L * 60 * 60;

        // 현재 시간
        long now = System.currentTimeMillis();

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expirationTime))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();

        // Refresh Token 생성 (여기서는 간단히 Access Token과 같은 방식으로 생성)
        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expirationTime * 2)) // Refresh Token은 더 긴 만료 시간
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();

        return new TokenDTO(accessToken, refreshToken);

    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(accessToken)
            .getBody();

        Collection<? extends GrantedAuthority> authorities =
            Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, accessToken, authorities);
    }

    //액세스 토큰과 리프레시 토큰 함께 재발행
    public TokenDTO reissueToken(String refreshToken) {
        if (!validateToken(refreshToken)) {
            throw new RuntimeException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 리프레시 토큰에서 claims 가져오기
        Claims claims = getClaims(refreshToken);
        String username = claims.getSubject();

        // 사용자의 권한 가져오기 (여기서는 ROLE_USER만 사용하는 예시)
        Collection<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(AUTHORITIES_KEY));

        // 새로운 액세스 토큰 생성
        String newAccessToken = Jwts.builder()
                .setSubject(username)
                .claim(AUTHORITIES_KEY, authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(",")))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // 30분 후 만료
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();

        // 새로운 리프레시 토큰 생성 (옵션)
        String newRefreshToken = Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 7일 후 만료
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();

        // 토큰 DTO 반환
        return new TokenDTO(newAccessToken, newRefreshToken);

    }

    public TokenDTO resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7); // "Bearer " 다음부터의 문자열 추출
            return new TokenDTO(token, null); // Refresh Token은 null로 반환
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {

            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {

            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {

            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {

            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }
}
