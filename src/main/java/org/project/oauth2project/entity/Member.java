package org.project.oauth2project.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Member {
	private String username;
	private String email;
	private String role;

	public GrantedAuthority getAuthority() {
		return new SimpleGrantedAuthority("ROLE_" + role.toUpperCase());
	}
}
