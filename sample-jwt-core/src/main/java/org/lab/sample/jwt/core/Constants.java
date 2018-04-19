package org.lab.sample.jwt.core;

public interface Constants {

	public interface Configuration {
		String PropertySource = "classpath:application.properties";
		String ComponentScan = "org.lab.sample.jwt";
		String DateFormat = "yyyy-MM-dd";
	}

	public interface Security {
		String HeaderAuthorization = "Authorization";
		String TokenBearerPrefix = "Bearer";
		String TokenIssuerInfo = "sample-jwt-core";
		String KeyClaimRoles = "appRoles";
	}

	public interface Roles {
		String Customer = "Customer";
		String Publisher = "Publisher";
	}

}
