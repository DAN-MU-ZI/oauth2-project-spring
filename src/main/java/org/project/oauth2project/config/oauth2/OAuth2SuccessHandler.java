package org.project.oauth2project.config.oauth2;

import java.io.IOException;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler  {
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		// 사용자 정보 가져오기 (필요에 따라 커스텀)
		Object principal = authentication.getPrincipal();
		log.info("OAuth2 로그인 성공: {}", principal);

		// 추가 정보 로그
		log.debug("details: {}", authentication.getDetails());
		log.debug("authorities: {}", authentication.getAuthorities());

		// 리다이렉트 등 처리는 필요에 따라 구현
		response.sendRedirect("/");
	}
}
