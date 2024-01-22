package com.demo.Authentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ApplicationAuthenticationFilter extends OncePerRequestFilter {
    public ApplicationAuthenticationFilter() {
        super();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String userName = request.getHeader("X-Forwarded-UserName");
        String email = request.getHeader("X-Forwarded-Email");
        List<String> roles = Collections.list(request.getHeaders("X-Forwarded-Roles"));
        User user = new User(userName, userName,
                roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user,
                null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        LoggedInUserContext.setLoggedInUser(userName);
        LoggedInUserContext.setLoggedInUserRoles(roles);
        filterChain.doFilter(request, response);
    }
}
