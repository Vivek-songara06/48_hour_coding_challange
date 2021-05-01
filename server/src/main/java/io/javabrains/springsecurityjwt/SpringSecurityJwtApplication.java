package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.filters.JwtRequestFilter;
import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.models.AuthenticationResponse;
import io.javabrains.springsecurityjwt.util.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.Header;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;


@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

}

@RestController
class HelloWorldController {
    private String Client_id;
    private String uri;

    public String getClient_id() {
        return Client_id;
    }

    public void setClient_id(String client_id) {
        Client_id = client_id;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @RequestMapping(value = "/login")
    public ModelAndView login(String Clientid, String uri,String loginnotvalid) {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("loginForm");
        mv.addObject("loginnotvalid",loginnotvalid);
        setClient_id(Clientid);
        setUri(uri);
        return mv;
    }

    @RequestMapping(value = "/addAuthenticationRequest")
    public ResponseEntity<?> addAuthenticationRequest(AuthenticationRequest accinfo, HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("login");
        String path="";
        int login_error=0;
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(accinfo.getUsername(), String.valueOf(accinfo.getPassword().hashCode())));
        }
        catch (BadCredentialsException e) {
            path=req.getContextPath()+"login?Clientid=" +getClient_id()+"&uri="+getUri()+"&loginnotvalid=\"Either UserId or Password is Incorrect\"";
            login_error=1;
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(accinfo.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);
        mv.addObject("response", jwt);
        Cookie mycookie = new Cookie(getClient_id(), jwt);
        mycookie.setMaxAge(60*60);
        resp.addCookie(mycookie);
        if(login_error==0)
            path="http://localhost:8080"+getUri()+"?id_token=" + jwt + "&username=" + accinfo.getUsername()+"&Client_id="+getClient_id();
        resp.sendRedirect(path);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

}


@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService myUserDetailsService;
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {

        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable().authorizeRequests().antMatchers("/login","/addAuthenticationRequest").permitAll().anyRequest().authenticated().and().
                exceptionHandling().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

}