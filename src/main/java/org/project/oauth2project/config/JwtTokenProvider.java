package org.project.oauth2project.config;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.project.oauth2project.entity.Member;
import org.project.oauth2project.service.MemberService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secretKey;
	private final MemberService memberService;

	private final long tokenValidityInMilliseconds = 3600000;

	public String createToken(String username, List<String> roles) {
		Claims claims = Jwts.claims().setSubject(username);
		claims.put("roles", roles);

		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + tokenValidityInMilliseconds);

		return Jwts.builder()
			.setClaims(claims)
			.setIssuedAt(now)
			.setExpiration(expiryDate)
			.signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
			.compact();
	}

	public String getUsername(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(secretKey.getBytes())
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(secretKey.getBytes()).build().parseClaimsJws(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}

	public Authentication getAuthentication(String token) {
		if (validateToken(token)) {
			String email = getUsername(token);
			Optional<Member> memberOpt = memberService.findMemberByEmail(email);
			if (memberOpt.isPresent()) {

				Member member = memberOpt.get();
				UserDetails userDetails = new CustomUserDetails(member);
				Set<GrantedAuthority> authorities = Collections.singleton(member.getAuthority());
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, "",
					authorities);
				log.info("Authenticated user: {}", email);
				return auth;
			}
		}
		return null;
	}
}

