package org.project.oauth2project.handler;

import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HmacSigner {

	private static final String HMAC_ALGO = "HmacSHA256";
	private static final String SECRET = "your-very-secret-key";

	public static String sign(String value) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGO);
			SecretKeySpec keySpec = new SecretKeySpec(SECRET.getBytes(), HMAC_ALGO);
			mac.init(keySpec);
			byte[] hmac = mac.doFinal(value.getBytes());
			String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);
			return value + "." + signature;
		} catch (Exception e) {
			throw new IllegalStateException("Failed to sign value", e);
		}
	}

	public static String verifyAndExtract(String signedValue) {
		int idx = signedValue.lastIndexOf('.');
		if (idx <= 0) {
			throw new IllegalArgumentException("서명 형식이 올바르지 않습니다.");
		}
		String payload = signedValue.substring(0, idx);

		String expectedSig = sign(payload);

		if (!signedValue.equals(expectedSig)) {
			throw new IllegalArgumentException("서명 검증 실패");
		}
		return payload;
	}
}