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
import org.springframework.web.client.RestTemplate;
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
    public final String Client_id = "9999";
    public final String callbackuri="callback";
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;



    @RequestMapping(value = "/")
    public ModelAndView firstpage(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("start");
        resp.sendRedirect(req.getContextPath() + "/client");
        return mv;
    }

    @RequestMapping(value = "/client")
    public ModelAndView client(@CookieValue(value = Client_id, defaultValue = "0") String cookieval, HttpServletRequest http, HttpServletResponse response) throws IOException, InterruptedException {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("client");
        if (!cookieval.equals("0")) {
            //previous login exist
            if(jwtTokenUtil.isTokenExpired(cookieval)){
                response.sendRedirect("http://localhost:8081/"+ "login?Clientid=" + Client_id + "&uri=/"+callbackuri);
            }
            mv.addObject("jwt", cookieval);
            mv.addObject("user",jwtTokenUtil.extractUsername(cookieval));
        } else {
            //redirect to login
            TimeUnit.SECONDS.sleep(2);
            response.sendRedirect("http://localhost:8081/"+ "login?Clientid=" + Client_id + "&uri=/"+callbackuri);
        }
        return mv;
    }


    @RequestMapping(value =  callbackuri)
    public ModelAndView callback(String Client_id,String id_token, String username) {
        ModelAndView mv = new ModelAndView();
        if(Client_id.equals(this.Client_id)){
            mv.addObject("timeleft", jwtTokenUtil.extractExpiration(id_token));
            mv.addObject("token", id_token);
            mv.addObject("extusername", jwtTokenUtil.extractUsername(id_token));
            mv.addObject("givenusername", username);
            mv.addObject("expired", jwtTokenUtil.isTokenExpired(id_token));
            mv.addObject("validate", jwtTokenUtil.validateToken(id_token, username));
            mv.setViewName("callback");
        }
        else{
            mv.addObject("thisclient",this.Client_id);
            mv.addObject("client",Client_id);
            mv.addObject("isvaliduser",true);
            mv.setViewName("invalid_callback");
        }
        return mv;
    }
}


@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

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
        httpSecurity.csrf().disable().authorizeRequests().antMatchers( "/client","/", "/callback").permitAll().anyRequest().authenticated().and().
                exceptionHandling().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

}