package org.project.oauth2project.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Member {
	private String username;
	private String email;
	private String role;
}
