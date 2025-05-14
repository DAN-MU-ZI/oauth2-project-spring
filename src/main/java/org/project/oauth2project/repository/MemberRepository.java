package org.project.oauth2project.repository;

import java.util.Optional;

import org.project.oauth2project.entity.Member;

public interface MemberRepository {
	Member save(Member member);

	Optional<Member> findByEmail(String email);

	Optional<Member> findByUsername(String username);

	void deleteByEmail(String email);

	void delete(Member member);
}
