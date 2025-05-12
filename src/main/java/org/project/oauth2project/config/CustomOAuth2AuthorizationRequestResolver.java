package org.project.oauth2project.config;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
	private final OAuth2AuthorizationRequestResolver delegate;

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		if (request == null) return null;

		OAuth2AuthorizationRequest resolve = delegate.resolve(request);

		return custom(request, resolve);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		if (request == null) return null;

		OAuth2AuthorizationRequest resolve = delegate.resolve(request, clientRegistrationId);

		return custom(request, resolve);
	}

	private OAuth2AuthorizationRequest custom(HttpServletRequest request, OAuth2AuthorizationRequest resolve) {
		if (resolve == null) return null;

		String role = request.getParameter("role");

		return OAuth2AuthorizationRequest.from(resolve)
			.attributes(attrs -> attrs.put("role", role))
			.build();
	}

}
