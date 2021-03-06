package org.lab.sample.jwt.web;

import org.lab.sample.jwt.core.security.JWTAuthenticationFilter;
import org.lab.sample.jwt.core.security.JWTAuthorizationFilter;
import org.lab.sample.jwt.core.services.TimeStampProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;

	@Autowired
	private TimeStampProvider timeStampProvider;

	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception { //@formatter:off
		log.debug("Configuring security");
		String authorizationPath = env.getProperty("app.env.jwt.authorization.path");
		AuthenticationManager authenticationManager = authenticationManager();
		
		JWTAuthenticationFilter authenticationFilter = new JWTAuthenticationFilter(authenticationManager(), env, timeStampProvider);
		authenticationFilter.setFilterProcessesUrl(authorizationPath);
				
		httpSecurity
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			.cors()
				.and()
			.csrf()
				.disable()
			.authorizeRequests()
				.antMatchers(HttpMethod.POST, authorizationPath).permitAll()
				.anyRequest().authenticated()
				.and()
			.addFilter(authenticationFilter)
			.addFilter(new JWTAuthorizationFilter(authenticationManager, env, timeStampProvider));

	} //@formatter:on

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.debug("Configuring AuthenticationManager");
		auth.userDetailsService(userDetailsService);
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}
}
