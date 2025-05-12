package org.project.oauth2project.config;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {
	private final LoggingInterceptor loggingInterceptor;

	// @Override
	// public void addInterceptors(InterceptorRegistry registry) {
	// 	registry.addInterceptor(loggingInterceptor)
	// 		.addPathPatterns("/**")      // 모든 경로에 적용
	// 		.excludePathPatterns("/css/**", "/js/**", "/images/**"); // 정적 리소스 제외
	// }
}
