package org.lab.sample.jwt.core.security;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.lab.sample.jwt.core.Constants;
import org.lab.sample.jwt.core.services.TimeStampProvider;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

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
			String header = request.getHeader(Constants.Security.HeaderAuthorization);
			Assert.notNull(header, "Missing header " + Constants.Security.HeaderAuthorization);
			Assert.isTrue(header.startsWith("Basic "), "Expected basic authorization header");
			String b64 = header.replace("Basic ", StringUtils.EMPTY);
			String decoded = new String(Base64.getDecoder().decode(b64), Charset.forName("UTF-8"));
			int index = decoded.indexOf(":");
			Assert.isTrue(index > 0, "Invalid credentials");
			String username = decoded.substring(0, index);
			String password = decoded.substring(index + 1, decoded.length());
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken( //@formatter:off
				username,
				password,
				new ArrayList<>()); //@formatter:on
			return authenticationManager.authenticate(token);
		}
		catch (Exception ex) {
			throw new InternalAuthenticationServiceException("Authentication error", ex);
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
		response.addHeader(Constants.Security.HeaderAuthorization, Constants.Security.TokenBearerPrefix + " " + token);
	}

	private String createToken(Authentication auth) {
		Integer expiration = env.getProperty("app.env.jwt.expiration", Integer.class);
		String secret = env.getProperty("app.env.jwt.secret");
		Date now = timeStampProvider.getCurrentDate();
		Date expirationDate = new DateTime(now).plusMinutes(expiration).toDate();
		String username = ((User) auth.getPrincipal()).getUsername();
		List<String> roles = auth.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.toList());

		String token = Jwts.builder() //@formatter:off
			.setIssuedAt(now)
			.setIssuer(Constants.Security.TokenIssuerInfo)
			.setSubject(username)
			.claim(Constants.Security.KeyClaimRoles, roles)
			.setExpiration(expirationDate)
			.signWith(SignatureAlgorithm.HS512, secret)
			.compact(); //@formatter:on

		return token;
	}
}