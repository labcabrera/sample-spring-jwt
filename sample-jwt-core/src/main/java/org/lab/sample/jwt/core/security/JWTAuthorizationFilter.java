package org.lab.sample.jwt.core.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private Environment env;

	public JWTAuthorizationFilter(AuthenticationManager authManager, Environment env) {
		super(authManager);
		this.env = env;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
		throws IOException, ServletException {
		String header = req.getHeader(SecurityConstants.HEADER_AUTHORIZACION_KEY);
		if (header == null || !header.startsWith(SecurityConstants.TOKEN_BEARER_PREFIX)) {
			chain.doFilter(req, res);
			return;
		}
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String header = request.getHeader(SecurityConstants.HEADER_AUTHORIZACION_KEY);
		if (header != null) {
			String secret = env.getProperty("app.env.jwt.secret");
			String token = header.replace(SecurityConstants.TOKEN_BEARER_PREFIX, StringUtils.EMPTY);
			Jws<Claims> claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
			String user = claims.getBody().getSubject();
			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
			}
			return null;
		}
		return null;
	}
}