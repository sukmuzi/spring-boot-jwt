package com.jwt.tutorial.controller;

import com.jwt.tutorial.dto.UserDto;
import com.jwt.tutorial.entity.User;
import com.jwt.tutorial.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {

    private final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@Valid @RequestBody UserDto userDto) {
        return ResponseEntity.ok(userService.singup(userDto));
    }

    // USER, ADMIN 권한 허용
    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public ResponseEntity<User> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    // ADMIN 권한만 허용
    // 권한이 맞지 않을 경우 JwtAccessDeniedHandler 발생
    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        logger.debug("user role : " + userService.getUserWithAuthorities(username).get().getAuthorities());

        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}
