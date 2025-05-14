package org.project.oauth2project.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.project.oauth2project.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.RequiredArgsConstructor;

public class CustomUserDetails implements UserDetails {
	private final Member member;

	public CustomUserDetails(Member member) {
		this.member = member;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singleton(member.getAuthority());
	}

	@Override
	public String getPassword() {
		return "";
	}

	@Override
	public String getUsername() {
		return member.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
