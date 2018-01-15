package com.example.secure.demoSecurityCustom.utilities;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

//VERY IMPORTANT:
//if you add these annotations you can remove SecurityConfig.java
//the difference is that instead of a login alert, a login web page is showed
     //@EnableWebSecurity
     //@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
//


//@Component
public class CustomAuthenticationProvider {}/*implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication auth)
            throws AuthenticationException {
        String username = auth.getName();
        String password = auth.getCredentials()
                .toString();

        if ("user".equals(username) && "pwd".equals(password)) {
            List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new UsernamePasswordAuthenticationToken(username, password, grantedAuths);
        } else {
            throw new BadCredentialsException("External system authentication failed");
            //return null;
        }
    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(UsernamePasswordAuthenticationToken.class);
    }
}
**/

