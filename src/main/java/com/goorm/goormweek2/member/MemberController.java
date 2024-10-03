package com.goorm.goormweek2.member;

import com.goorm.goormweek2.member.MemberDTO.GeneralDto;
import com.goorm.goormweek2.security.token.TokenDTO;
import com.goorm.goormweek2.security.token.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class MemberController {

    MemberService memberService;
    private final TokenProvider tokenProvider;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody GeneralDto memberDto) {
        memberService.register(memberDto.getEmail(), memberDto.getPassword());
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<Cookie> login(@RequestBody GeneralDto generalDto) {
        TokenDTO token = memberService.login(generalDto.getEmail(), generalDto.getPassword());

        // 쿠키 생성
        Cookie accessTokenCookie = new Cookie("accessToken", token.getAccessToken());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/"); // 쿠키가 적용될 경로 설정

        Cookie refreshTokenCookie = new Cookie("refreshToken", token.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");

        // 쿠키를 응답에 추가
        ResponseEntity<Cookie> response = ResponseEntity.ok()
                .header("Set-Cookie", accessTokenCookie.toString())
                .header("Set-Cookie", refreshTokenCookie.toString())
                .body(accessTokenCookie); // 첫 번째 쿠키를 바디로 반환

        return response;
    }

    @DeleteMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();  // 세션 무효화
        }

        // 로그아웃 시 쿠키 삭제
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");

        // 쿠키를 응답에 추가
        ResponseEntity<String> response = ResponseEntity.ok()
                .header("Set-Cookie", accessTokenCookie.toString())
                .header("Set-Cookie", refreshTokenCookie.toString())
                .body("로그아웃 성공");

        return response;
    }

    @GetMapping("/reissue")
    public ResponseEntity<Cookie> reissue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        // 리프레시 토큰이 없으면 401 에러 응답
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        // 리프레시 토큰으로 새로운 액세스 토큰을 발급받습니다.
        TokenDTO token = tokenProvider.reissueToken(refreshToken);

        // 쿠키 생성
        Cookie accessTokenCookie = new Cookie("accessToken", token.getAccessToken());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");

        ResponseEntity<Cookie> response = ResponseEntity.ok()
                .header("Set-Cookie", accessTokenCookie.toString())
                .body(accessTokenCookie); // 새로 발급된 쿠키 반환

        return response;
    }
}