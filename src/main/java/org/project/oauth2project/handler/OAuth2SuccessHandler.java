package org.project.oauth2project.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import org.project.oauth2project.service.MemberService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
	private final ObjectMapper mapper;
	private final MemberService memberService;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws
		IOException {

		OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken)auth;
		OAuth2User oauth2User = oauthToken.getPrincipal();

		String email = oauth2User.getAttribute("email");
		String username = oauth2User.getName();
		String desiredRole = extractRole(req);

		String existingRole = memberService.findOrCreateWithRole(email, username, desiredRole)
			.orElseThrow(() -> new OAuth2AuthenticationException("Member role does not match desired role"));

		Collection<GrantedAuthority> updated = new ArrayList<>(oauth2User.getAuthorities());
		updated.add(new SimpleGrantedAuthority("ROLE_" + existingRole.toUpperCase()));

		String nameKey = resolveNameAttributeKey(oauth2User);

		DefaultOAuth2User newPrincipal = new DefaultOAuth2User(updated, oauth2User.getAttributes(), nameKey);

		OAuth2AuthenticationToken newAuth = new OAuth2AuthenticationToken(newPrincipal, updated,
			oauthToken.getAuthorizedClientRegistrationId());
		newAuth.setDetails(oauthToken.getDetails());
		SecurityContextHolder.getContext().setAuthentication(newAuth);

		res.sendRedirect("/");
	}

	private String extractRole(HttpServletRequest req) {
		String rawState = req.getParameter("state");
		if (rawState == null) {
			log.warn("missing state");
			throw new OAuth2AuthenticationException(new OAuth2Error("missing_state"));
		}
		String payload = HmacSigner.verifyAndExtract(rawState);
		try {
			return mapper.readTree(payload).get("role").asText();
		} catch (Exception e) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_state"), e.getMessage(), e);
		}
	}

	private String resolveNameAttributeKey(OAuth2User principal) {
		String nameValue = principal.getName();

		return principal.getAttributes().entrySet().stream()
			.filter(entry -> Objects.equals(entry.getValue().toString(), nameValue))
			.map(Map.Entry::getKey)
			.findFirst()
			.orElseThrow(() ->
				new IllegalStateException("Cannot resolve nameAttributeKey from principal attributes")
			);
	}

}
