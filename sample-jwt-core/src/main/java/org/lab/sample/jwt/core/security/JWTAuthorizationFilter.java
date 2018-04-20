package org.lab.sample.jwt.core.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.lab.sample.jwt.core.Constants;
import org.lab.sample.jwt.core.services.TimeStampProvider;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private final Environment env;
	private final TimeStampProvider timeStampProvider;

	public JWTAuthorizationFilter(AuthenticationManager authManager, Environment env,
		TimeStampProvider timeStampProvider) {
		super(authManager);
		this.env = env;
		this.timeStampProvider = timeStampProvider;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		String header = request.getHeader(Constants.Security.HeaderAuthorization);
		if (header == null || !header.startsWith(Constants.Security.TokenBearerPrefix)) {
			chain.doFilter(request, response);
			return;
		}
		try {
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);
		}
		catch (SignatureException ex) {
			handleException(ex, response);
		}
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		UsernamePasswordAuthenticationToken result = null;
		String header = request.getHeader(Constants.Security.HeaderAuthorization);
		if (header != null) {
			log.debug("JWT validation attempt");
			String secret = env.getProperty("app.env.jwt.secret");
			String token = header.replace(Constants.Security.TokenBearerPrefix, StringUtils.EMPTY);

			Jws<Claims> claims = Jwts //@formatter:off
				.parser()
				.setClock(new InternalClock(timeStampProvider))
				.setSigningKey(secret)
				.parseClaimsJws(token);
				//@formatter:on

			String user = claims.getBody().getSubject();
			if (user != null) {
				List<GrantedAuthority> grantedAuthorities = readGrantedAuthorities(claims);
				result = new UsernamePasswordAuthenticationToken(user, null, grantedAuthorities);
			}
			else {
				log.debug("Missing subject in JWT token");
			}
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private List<GrantedAuthority> readGrantedAuthorities(Jws<Claims> claims) {
		List<GrantedAuthority> result = new ArrayList<>();
		ArrayList<String> roles = (ArrayList<String>) claims.getBody().get(Constants.Security.KeyClaimRoles);
		if (roles != null) {
			roles.forEach(i -> result.add(new SimpleGrantedAuthority(i)));
		}
		return result;
	}

	private void handleException(Exception ex, HttpServletResponse response) {
		log.debug("Invalid JWT token", ex);
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@AllArgsConstructor
	private static class InternalClock implements Clock {

		private final TimeStampProvider timeStampProvider;

		@Override
		public Date now() {
			return timeStampProvider.getCurrentDate();
		}

	}
}