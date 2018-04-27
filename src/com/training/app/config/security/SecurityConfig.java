
package com.training.app.config.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  DataSource dataSource;

  @Bean
  public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("user").password("password").roles("USER").build());
    return manager;
  }

  //1. Default
  //Default configuration in WebSecurityConfigurerAdapter
  /*@Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .and()
        .httpBasic();
  }*/

  //2. Similar Configuration to Xml Config
  /*@Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/admin").access("hasRole('ROLE_ADMIN')").anyRequest().authenticated()
        .antMatchers("/home**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .antMatchers("/welcome**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .antMatchers("/**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .and()
        .exceptionHandling().accessDeniedPage("/accessdenied")
        .and()
        .formLogin()
        .and()
        .httpBasic()
        .and()
        .logout().logoutSuccessUrl("/login?logout").invalidateHttpSession(true)
        .and()
        .sessionManagement().invalidSessionUrl("/sessionTimeout").maximumSessions(1);
  }*/

  //3. Http Basic Authentication
  /*protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/admin").hasRole("ROLE_ADMIN").anyRequest().fullyAuthenticated()
        .antMatchers("/home**").hasAnyRole("ROLE_ADMIN", "ROLE_USER").anyRequest().fullyAuthenticated()
        .antMatchers("/welcome**").hasAnyRole("ROLE_ADMIN", "ROLE_USER").anyRequest().fullyAuthenticated()
        .antMatchers("/**").hasAnyRole("ROLE_ADMIN", "ROLE_USER").anyRequest().fullyAuthenticated()
        .and()
        .httpBasic()
        .and()
        .exceptionHandling().accessDeniedPage("/accessdenied")
        .and()
        .logout().logoutSuccessUrl("/login?logout").invalidateHttpSession(true)
        .and()
        .sessionManagement().invalidSessionUrl("/sessionTimeout").maximumSessions(1);
  }*/

  //4. Override Default configuration in WebSecurityConfigurerAdapter for custom login form instead auto generated login form by spring security
  //The updated configuration specifies the location of the log in page.
  //We must grant all users (i.e. unauthenticated users) access to our log in page
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/login**").permitAll()
        .antMatchers("/admin").access("hasRole('ROLE_ADMIN')").anyRequest().authenticated()
        .antMatchers("/home**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .antMatchers("/welcome**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .antMatchers("/**").access("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')").anyRequest().authenticated()
        .and()
        .formLogin().loginPage("/login").loginProcessingUrl("/j_spring_security_check").defaultSuccessUrl("/", true)
        .failureUrl("/login?error").usernameParameter("username").passwordParameter("password")
        .and()
        .exceptionHandling().accessDeniedPage("/accessdenied")
        .and()
        .logout().logoutSuccessUrl("/login?logout").invalidateHttpSession(true)
        .and()
        .sessionManagement().invalidSessionUrl("/sessionTimeout").maximumSessions(1);
	}

  //5. Customization to authorize request
  //Override Default configuration in WebSecurityConfigurerAdapter for custom login form and authorize requests
  //We specified multiple URL patterns that any user can access like "/resources/", "/scripts/", "/css/" etc.
  //Any URL that starts with "/admin/" will be restricted to users who have the role "ROLE_ADMIN".
  //Any URL that starts with "/db/" requires the user to have both "ROLE_ADMIN" and "ROLE_DBA".
  //Any URL that has not already been matched on only requires that the user be authenticated
	/*@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()                                                                
				.antMatchers("/resources/**", "/signup", "/about").permitAll()                  
				.antMatchers("/admin/**").hasRole("ADMIN")                                      
				.antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")            
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
			.and()
			.logout()
			.permitAll();
	}*/


  //In memory authentication java configuration
  //Not web-specific
	/*@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
        .passwordEncoder(new BCryptPasswordEncoder())
				.withUser("user").password("$2a$10$iFl1wjuT46oXhpXKSPet3O4ImJEvJsqg3H.Zyz3jPTeLWQn/MHy4.").authorities("ROLE_USER").and()
				.withUser("admin").password("$2a$10$.OxKBZeH7nhXh9XC58iLUOAxkg066OjwxZuKaXeLD/FIb9JXngWvy").authorities("ROLE_ADMIN");
	}*/

  /*JDBC Authentication
  Provides default queries
   SELECT username, password, enabled FROM users WHERE username = ?
   SELECT username, authority FROM authorities WHERE username = ?
  We can customize the default queries by using following methods
  usersByUsernameQuery()
  authoritiesByUsernameQuery()
  groupAuthoritiesByUsername()*/

  @Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.jdbcAuthentication()
        .passwordEncoder(new BCryptPasswordEncoder())
			.usersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?")
			.authoritiesByUsernameQuery("SELECT username, authority FROM authorities WHERE username = ?")
			.dataSource(dataSource);
	}
}
