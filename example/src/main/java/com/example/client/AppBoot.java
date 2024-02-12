package com.example.client;

import java.util.Date;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class AppBoot {

    public static void main(final String[] args) {
        SpringApplication.run(AppBoot.class, args);
    }

    @GetMapping(path = { "/" })
    public String ping() {
        return "Now is " + new Date();
    }
    
    @GetMapping(path = { "/auth/ping" })
    public String authPing(Authentication authentication) {
        return "Subject:("+authentication.getName()+") Claims:" + authentication.getDetails();
    }
}
