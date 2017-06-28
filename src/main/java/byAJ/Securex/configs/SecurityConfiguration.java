package byAJ.Securex.configs;

import byAJ.Securex.repositories.UserRepository;
import byAJ.Securex.services.SSUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity

public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
@Autowired
private UserRepository userRepository;

@Override
public UserDetailsService userDetailsServiceBean() throws Exception{
    return new SSUserDetailsService(userRepository);
}
    @Override
    protected void configure(HttpSecurity http) throws Exception {

    http
                .authorizeRequests().antMatchers("/", "/books/list","/css/**").permitAll()
                .antMatchers("/books/edit/**").hasRole("ADMIN")
                       .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .permitAll()
                .and()
                .httpBasic();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth.userDetailsService(userDetailsServiceBean());
    /*auth.inMemoryAuthentication().withUser("user").password("password").roles("USER").and().
                withUser("root").password("password2").roles("ADMIN").and().
                withUser("Dave").password("begreat").roles("ADMIN").and().
        withUser("Fi").password("becold").roles("ADMIN");*/
    }
}
