package org.lab.sample.jwt.core.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.lab.sample.jwt.core.Constants;
import org.lab.sample.jwt.core.model.UserInfo;
import org.lab.sample.jwt.core.services.TimeStampProvider;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final Environment env;
	private final TimeStampProvider timeStampProvider;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.web.authentication.
	 * UsernamePasswordAuthenticationFilter#attemptAuthentication(javax.servlet.
	 * http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		log.debug("Attempting authentication");
		try {
			UserInfo credenciales = new ObjectMapper().readValue(request.getInputStream(), UserInfo.class);
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				credenciales.getUsername(), credenciales.getPassword(), new ArrayList<>());
			return authenticationManager.authenticate(token);
		}
		catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.web.authentication.
	 * AbstractAuthenticationProcessingFilter#successfulAuthentication(javax.
	 * servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * javax.servlet.FilterChain,
	 * org.springframework.security.core.Authentication)
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication auth) throws IOException, ServletException {
		String token = createToken(auth);
		response.addHeader(Constants.Security.HEADER_AUTHORIZACION_KEY,
			Constants.Security.TOKEN_BEARER_PREFIX + " " + token);
	}

	private String createToken(Authentication auth) {
		Integer expiration = env.getProperty("app.env.jwt.expiration", Integer.class);
		String secret = env.getProperty("app.env.jwt.secret");
		Date now = timeStampProvider.getCurrentDate();
		Date expirationDate = new DateTime(now).plusMinutes(expiration).toDate();
		String username = ((User) auth.getPrincipal()).getUsername();

		String token = Jwts.builder() //@formatter:off
			.setIssuedAt(now)
			.setIssuer(Constants.Security.ISSUER_INFO)
			.setSubject(username)
			.claim(Constants.Security.KeyClaimRoles, Arrays.asList("role1", "role2"))
			.setExpiration(expirationDate)
			.signWith(SignatureAlgorithm.HS512, secret)
			.compact(); //@formatter:on

		return token;
	}
}