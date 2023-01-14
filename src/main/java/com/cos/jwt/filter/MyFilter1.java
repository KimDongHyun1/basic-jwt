package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class MyFilter1 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// 토큰: ID와 PASSWORD가 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들어주고 응답해준다.
		// 요청할때마다 Header에 Authoration에 Value값으로 토큰을 가져올때
		// 토큰이 넘어오면 내가 만든 토큰이 맞는지만 검증	해주면된다.
		
		if(req.getMethod().equals("POST")) {
			System.out.println("POST !!!");
			String headerAuth = req.getHeader("Authorization");
			
			if(headerAuth.equals("COS")) {
				chain.doFilter(req, res);
			} else {
				
				PrintWriter out = res.getWriter();
				out.println("인증 안됨");
			}
			
		} else if(req.getMethod().equals("GET")) {
			System.out.println("GET !!!");
			
			
		}
		
		System.out.println("필터 11111");
		chain.doFilter(request, response);
	}

	
}
