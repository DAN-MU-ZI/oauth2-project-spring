package org.project.oauth2project.handler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.project.oauth2project.config.JwtTokenProvider;
import org.project.oauth2project.entity.Member;
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

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
	private final ObjectMapper mapper;
	private final MemberService memberService;
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws
		IOException {

		OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken)auth;
		OAuth2User oauth2User = oauthToken.getPrincipal();

		String email = oauth2User.getAttribute("email");
		String username = oauth2User.getName();
		String desiredRole = extractRole(req);

		try {
			Member member = memberService.findOrCreateMember(email, username, desiredRole);
			memberService.validateMemberRole(member, desiredRole);

			// 권한 추가
			Collection<GrantedAuthority> updatedAuthorities = new ArrayList<>(oauth2User.getAuthorities());
			updatedAuthorities.add(member.getAuthority());

			// 토큰 생성
			List<String> roles = Collections.singletonList(member.getAuthority().getAuthority());
			String token = jwtTokenProvider.createToken(email, roles);
			Cookie cookie = getCookie(token);
			res.addCookie(cookie);

			// 새로운 Principal 설정
			String nameKey = resolveNameAttributeKey(oauth2User);
			DefaultOAuth2User newPrincipal = new DefaultOAuth2User(updatedAuthorities, oauth2User.getAttributes(), nameKey);
			OAuth2AuthenticationToken newAuth = new OAuth2AuthenticationToken(newPrincipal, updatedAuthorities, oauthToken.getAuthorizedClientRegistrationId());
			newAuth.setDetails(oauthToken.getDetails());
			SecurityContextHolder.getContext().setAuthentication(newAuth);

			res.sendRedirect("/");

		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			HttpSession session = req.getSession(false);
			if (session != null) {
				session.invalidate();
			}
			throw ex;
		}
	}

	private static Cookie getCookie(String token) {
		Cookie cookie = new Cookie("accessToken", token);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath("/");
		cookie.setMaxAge(3600);
		return cookie;
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
