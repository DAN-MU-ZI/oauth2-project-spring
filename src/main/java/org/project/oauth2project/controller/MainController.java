package org.project.oauth2project.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/")
public class MainController {
	@GetMapping("/")
	public String home(Model model, Authentication authentication) {
		log.info("Current user: {}", authentication);
		if (authentication != null) {
			authentication.getAuthorities()
				.stream()
				.filter(auth -> auth.getAuthority().startsWith("ROLE_"))
				.findFirst()
				.ifPresent(role -> {
					log.info("find role : {}", role.getAuthority());
					model.addAttribute("name", authentication.getName());
					model.addAttribute("role", role.getAuthority());
				});
		}
		log.info("requested granted authority: {}", authentication);
		return "index";
	}
}
