package com.example.secure.demoSecurityCustom;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;

@SpringBootApplication
public class DemoSecurityCustomApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoSecurityCustomApplication.class, args);
	}
}
