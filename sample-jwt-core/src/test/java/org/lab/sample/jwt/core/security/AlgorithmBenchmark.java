package org.lab.sample.jwt.core.security;

import java.io.InputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.lab.sample.jwt.core.Constants;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Data;

public class AlgorithmBenchmark implements Runnable {

	public static void main(String[] args) {
		new AlgorithmBenchmark().run();
	}

	public void run() {
		int count = 10000;
		KeyPair rsaKey = readKeyRSA();
		KeyPair ecKey = readKeyEC();

		KeyHolder secretKeyHolder = new KeyHolder("secret".getBytes(), null, null);
		KeyHolder rsaKeyHolder = new KeyHolder(null, rsaKey.getPublic(), rsaKey.getPrivate());
		KeyHolder ecKeyHolder = new KeyHolder(null, ecKey.getPublic(), ecKey.getPrivate());

		for (String name : new String[] { "RS256", "RS384", "RS512" }) {
			runAlg(SignatureAlgorithm.valueOf(name), rsaKeyHolder, count);
		}
		for (String name : new String[] { "HS256", "HS384", "HS512" }) {
			runAlg(SignatureAlgorithm.valueOf(name), secretKeyHolder, count);
		}
		System.out.println("Following alg requires bouncycastle");
		for (String name : new String[] { "ES256", "ES384", "ES512" }) {
			runAlg(SignatureAlgorithm.valueOf(name), ecKeyHolder, count);
		}
		for (String name : new String[] { "PS256", "PS384", "PS512" }) {
			runAlg(SignatureAlgorithm.valueOf(name), rsaKeyHolder, count);
		}
	}

	private void runAlg(SignatureAlgorithm alg, KeyHolder holder, int count) {
		try {
			String token = null;
			long t0;
			long t;
			BigDecimal avg;
			System.out.println("--------------------------------------------------------");
			System.out.println(alg + " (" + alg.getDescription() + ")");
			t0 = System.currentTimeMillis();
			for (int i = 0; i < count; i++) {
				token = generateToken(alg, holder);
			}
			t = System.currentTimeMillis() - t0;
			avg = new BigDecimal(t).divide(new BigDecimal(count), 5, RoundingMode.HALF_EVEN);
			System.out.println("  generate: " + t + "ms (" + avg + " ms avg)");
			t0 = System.currentTimeMillis();
			for (int i = 0; i < count; i++) {
				validateToken(token, holder);
			}
			t = System.currentTimeMillis() - t0;
			avg = new BigDecimal(t).divide(new BigDecimal(count), 5, RoundingMode.HALF_EVEN);
			System.out.println("  validate: " + t + "ms (" + avg + " avg)");
		}
		catch (Exception ex) {
			ex.printStackTrace(System.out);
		}
	}

	private KeyPair readKeyRSA() {
		try {
			ClassLoader cl = Thread.currentThread().getContextClassLoader();
			InputStream in = cl.getResourceAsStream("sample-spring-jwt.p12");
			KeyStore keystore = KeyStore.getInstance("pkcs12");
			keystore.load(in, "changeit".toCharArray());
			String alias = "sample-spring-jwt";
			Key key = keystore.getKey(alias, "changeit".toCharArray());
			Certificate certificate = keystore.getCertificate(alias);
			return new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private KeyPair readKeyEC() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
			KeyPairGenerator g = (KeyPairGenerator) KeyPairGenerator.getInstance("ECDSA", "BC");
			g.initialize(ecSpec, new SecureRandom());
			return g.generateKeyPair();
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}

	}

	private String generateToken(SignatureAlgorithm alg, KeyHolder holder) {
		JwtBuilder builder = Jwts.builder() //@formatter:off
			.setIssuedAt(Calendar.getInstance().getTime())
			.setIssuer(Constants.Security.TokenIssuerInfo)
			.setSubject("subject")
			.claim(Constants.Security.KeyClaimRoles, Arrays.asList("A", "B", "C"))
			.setExpiration(new Date(System.currentTimeMillis() + 6000000)); //@formatter:on
		if (holder.getSecret() != null) {
			builder = builder.signWith(alg, holder.getSecret());
		}
		else {
			builder = builder.signWith(alg, holder.getPrivateKey());
		}
		return builder.compact();
	}

	private void validateToken(String token, KeyHolder holder) {
		if (holder.getSecret() != null) {
			Jwts.parser().setSigningKey(holder.getSecret()).parseClaimsJws(token);
		}
		else {
			Jwts.parser().setSigningKey(holder.getPublicKey()).parseClaimsJws(token);
		}
	}

	@Data
	@AllArgsConstructor
	private class KeyHolder {
		private byte[] secret;
		private PublicKey publicKey;
		private PrivateKey privateKey;
	}

}
