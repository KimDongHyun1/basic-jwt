package com.cos.jwt.config.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * 시큐리티가 Filter를 가지고 있는데 그 Filter중에 BasicAuthenticationFilter 라는 것이 있다.
 * 인증이나 권한이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있다.
 * 만약에 인증이나 권한이 필요한 주소가 아니라면 이 필터를 타지 않는다.
 */

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	@Autowired
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	// 인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 타게 됨
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
//		super.doFilterInternal(request, response, chain);
		
		System.out.println("인증이나 권한이 필요한 요청이 들어옴");
		String jwtHeader = request.getHeader("Authorization");
		
		// Header 체크
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT Token을 검증해서 정상적인 요청인지 체크한다.
		String jwtToken = jwtHeader.replace("Bearer ", "");
		
		String username = JWT.require(Algorithm.HMAC512("김동현"))
							.build()
							.verify(jwtToken)
							.getClaim("username")
							.asString();
		
		// 서명이 정상적으로 됨
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
			Authentication authentication = 
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());;
		
			// Security Session에 Authentication 객체를 넣어준다.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
		
	}
	
}
