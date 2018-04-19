package org.lab.sample.jwt.web;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

import org.lab.sample.jwt.core.Constants;
import org.lab.sample.jwt.core.Constants.Roles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@ComponentScan(Constants.Configuration.ComponentScan)
@PropertySource(Constants.Configuration.PropertySource)
@EnableWebMvc
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebConfig extends WebMvcConfigurerAdapter {

	@Override
	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		log.debug("Configuring message converters");
		Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
		builder.indentOutput(true).dateFormat(new SimpleDateFormat(Constants.Configuration.DateFormat));
		converters.add(new MappingJackson2HttpMessageConverter(builder.build()));
	}

	@Bean
	UserDetailsService userDetailsService() {
		log.debug("Creating user detail service");
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		User alice = new User("alice", "alice", Arrays.asList(new SimpleGrantedAuthority("ROLE_" + Roles.Customer)));
		User bob = new User("bob", "bob", Arrays.asList(new SimpleGrantedAuthority("ROLE_" + Roles.Publisher)));
		manager.createUser(alice);
		manager.createUser(bob);
		return manager;
	}

}
