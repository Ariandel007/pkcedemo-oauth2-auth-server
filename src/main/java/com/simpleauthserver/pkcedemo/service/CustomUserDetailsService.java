package com.simpleauthserver.pkcedemo.service;

import com.simpleauthserver.pkcedemo.model.UserApp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserApp user = new UserApp();
        user.setId(1L);
        user.setUsername("alexander");
        user.setPassword("$2a$12$F4.cCUJJt8OsOMu..TJmPeZW9TSUbnZfR2qzBJtq5EK1s9hn234eW");//Peluso123
        user.setRoles("ROLE_USER,ROLE_ADMIN");

        List<GrantedAuthority> authorities = Arrays.stream(user.getRoles().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }
}
