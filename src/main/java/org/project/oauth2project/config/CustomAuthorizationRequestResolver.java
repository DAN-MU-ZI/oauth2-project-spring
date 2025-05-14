package org.project.oauth2project.config;

import java.util.Map;

import org.project.oauth2project.handler.HmacSigner;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
	private final OAuth2AuthorizationRequestResolver delegate;
	private final ObjectMapper mapper;

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		return customize(delegate.resolve(request), request);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		return customize(delegate.resolve(request, clientRegistrationId), request);
	}

	private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest req, HttpServletRequest request) {
		if (req == null)
			return null;

		String role = request.getParameter("role");
		if (role == null || role.isBlank()) {
			throw new RuntimeException("role is empty");
		}
		Map<String, String> param = Map.of("role", role);
		try {
			String serializedMap = mapper.writeValueAsString(param);
			String signedMap = HmacSigner.sign(serializedMap);

			log.debug("Encoded OAuth2 context: {}", signedMap);
			return OAuth2AuthorizationRequest.from(req).state(signedMap).build();
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}
}

