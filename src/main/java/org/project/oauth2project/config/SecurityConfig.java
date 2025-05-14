package org.project.oauth2project.config;

import org.project.oauth2project.handler.OAuth2SuccessHandler;
import org.project.oauth2project.service.MemberService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	private final ClientRegistrationRepository oAuth2ClientRegistrationRepository;
	private final ObjectMapper objectMapper;
	private final MemberService memberService;

	@Bean
	public OAuth2SuccessHandler oauth2SuccessHandler() {
		return new OAuth2SuccessHandler(objectMapper, memberService);
	}

	@Bean
	public OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver() {
		DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
			oAuth2ClientRegistrationRepository, "/oauth2/authorization");
		return new CustomAuthorizationRequestResolver(resolver, objectMapper);
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http
			// Basic 인증은 사용하지 않으므로 비활성화 (OAuth2 만 테스트)
			.httpBasic(AbstractHttpConfigurer::disable)

			// 기본 폼 로그인도 사용하지 않으므로 비활성화
			.formLogin(AbstractHttpConfigurer::disable)

			// H2 콘솔은 iframe 기반이라 sameOrigin 으로 허용
			.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))

			.csrf(AbstractHttpConfigurer::disable)

			// 모든 요청을 허용하여 인증 흐름 테스트에 집중
			.authorizeHttpRequests(req -> req.anyRequest().permitAll())

			// OAuth2 인가 코드 흐름 테스트를 위한 기본 로그인 설정
			.oauth2Login(oauth2 -> oauth2.authorizationEndpoint(
					auth -> auth.authorizationRequestResolver(oAuth2AuthorizationRequestResolver()))
				.successHandler(oauth2SuccessHandler()))

			// 로그아웃 설정 포함 (기본 흐름 이해 목적)
			.logout(logout -> logout.invalidateHttpSession(true).deleteCookies("JSESSIONID").logoutSuccessUrl("/"));

		return http.build();
	}
}

