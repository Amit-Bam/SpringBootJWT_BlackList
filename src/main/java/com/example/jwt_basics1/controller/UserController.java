package com.example.jwt_basics1.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    @GetMapping("/protected-message")
    public String home() {
        return "Welcome to the Backend Server home page";
    }

    @GetMapping("/protected-message-admin")
    public String adminHome() {
        return "Welcome to the Backend Server ADMIN home page";
    }

}
