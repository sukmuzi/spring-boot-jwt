package com.jwt.tutorial.controller;

import com.jwt.tutorial.dto.LoginDto;
import com.jwt.tutorial.dto.TokenDto;
import com.jwt.tutorial.jwt.JwtFilter;
import com.jwt.tutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    // TokenProvider, AuthenticationManagerBuilder 주입
    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        // username, password 파라미터로 받고 UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // authenticationToken 을 이용하여 authenticate 메소드가 실행될 때 loadUserByUsername 메소드 실행
        /**
         *  실행 순서
         *  1. AuthController.authorize() : 컨트롤러
         *  2. ProviderManager.authenticate() : 스프링 내부 라이브러리
         *  3. AbstractUserDetailsAuthenticationProvider.authenticate() : 스프링 내부 라이브러리
         *  4. DaoAuthenticationProvider.retrieveUser() : 스프링 내부 라이브러리
         *  5. CustomUserDetailsService.loadUserByUsername() : override 된 메소드
         */
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // Authentication 객체를 생성하고 SecurityContext 에 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // createToken 메소드를 통해 JWT Token 생성
        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
