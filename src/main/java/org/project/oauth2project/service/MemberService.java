package org.project.oauth2project.service;

import java.util.Optional;

import org.project.oauth2project.entity.Member;
import org.project.oauth2project.repository.MemberRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;



import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {
	private final MemberRepository memberRepository;

	public Optional<Member> getMemberByEmail(String email) {
		return memberRepository.findByEmail(email);
	}

	public String getRole(String email) {
		return getMemberByEmail(email).map(Member::getRole).orElse(null);
	}

	public Member createMember(String email, String username, String desiredRole) {
		log.info("Creating member with email: {}", email);
		Member m = new Member(username, email, desiredRole);
		return memberRepository.save(m);
	}

	public Optional<String> findOrCreateWithRole(String email, String username, String desiredRole) {
		String role = getRole(email);
		if (role == null) {
			role = createMember(email, username, desiredRole).getRole();
		} else if (!role.equals(desiredRole)) {
			log.info("Role is not matched {}", desiredRole);
			throw new OAuth2AuthenticationException(new OAuth2Error("role_mismatch"),
				"Member role does not match desired role");
		}
		return Optional.ofNullable(role);
	}

	public Optional<Member> findMemberByEmail(String email) {
		return memberRepository.findByEmail(email);
	}
}
