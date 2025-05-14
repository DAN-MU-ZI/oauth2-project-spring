package org.project.oauth2project.repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.project.oauth2project.entity.Member;
import org.springframework.stereotype.Repository;


import lombok.extern.slf4j.Slf4j;

@Slf4j
@Repository
public class MemberRepositoryImpl implements MemberRepository {
	private final Map<String, Member> members = new HashMap<>();

	@Override
	public Member save(Member member) {
		Member existing = members.get(member.getEmail());
		if (existing != null && !existing.getRole().equals(member.getRole())) {
			throw new RuntimeException("Member's role is not equals to existing member's role");
		}
		members.put(member.getEmail(), member);
		return members.get(member.getEmail());
	}

	@Override
	public Optional<Member> findByEmail(String email) {
		return Optional.ofNullable(members.get(email));
	}

	@Override
	public Optional<Member> findByUsername(String username) {
		return members.values().stream()
			.filter(m -> m.getUsername().equals(username))
			.findFirst();
	}

	@Override
	public void deleteByEmail(String email) {
		members.remove(email);
	}

	@Override
	public void delete(Member member) {
		members.remove(member.getEmail());
	}
}
