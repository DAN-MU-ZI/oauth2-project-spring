package org.project.oauth2project.config;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class LoggingInterceptor implements HandlerInterceptor {
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws
		Exception {

		String method = request.getMethod();
		String uri = request.getRequestURI();
		String query = request.getQueryString();
		String remoteIp = request.getRemoteAddr();

		StringBuilder sb = new StringBuilder();
		sb.append("Incoming Request → ")
			.append(method)
			.append(" ")
			.append(uri);
		if (query != null) {
			sb.append("?").append(query);
		}
		sb.append(" | from ").append(remoteIp);

		// 헤더 전체를 로그에 남기려면
		request.getHeaderNames().asIterator().forEachRemaining(name ->
			sb.append(" | ").append(name).append("=").append(request.getHeader(name))
		);

		log.info(sb.toString());
		return true;  // true를 반환해야 다음 인터셉터나 컨트롤러로 진행됩니다
	}
}
