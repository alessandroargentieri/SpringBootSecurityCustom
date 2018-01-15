package com.example.secure.demoSecurityCustom.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;

@org.springframework.web.bind.annotation.RestController
public class RestController {



    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("/hello")
    public String getResponse(){
        return "Welcome! You are correctly logged!";
    }

    @PreAuthorize("hasRole('ROLE_PAGLIACCIO')")
    @RequestMapping("/pagliaccio")
    public String getPagliaccioResponse(){
        return "Welcome! You are a pagliaccio!";
    }

    /*se cmq non configuro il passaggio di free in SecurityImpl passa cmq per il login ed è valido uno qualunque dei login se non specificato quale con @PreAuthorize*/
    @RequestMapping("/free")
    public String getFreeResponse(){
        return "Welcome! This is free!";
    }
}
