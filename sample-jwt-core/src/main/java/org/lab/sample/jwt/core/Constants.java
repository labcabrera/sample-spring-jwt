package org.lab.sample.jwt.core;

public interface Constants {

	public interface Configuration {
		String PropertySource = "classpath:application.properties";
		String ComponentScan = "org.lab.sample.jwt";
		String DateFormat = "yyyy-MM-dd";
	}

	public interface Security {

		String HEADER_AUTHORIZACION_KEY = "Authorization";
		String TOKEN_BEARER_PREFIX = "Bearer";
		String ISSUER_INFO = "sample-jwt-core";
	}

}
