/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.csrfguard.web.filter;

import org.apache.shiro.web.filter.AccessControlFilter;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 拷贝 org.owasp.csrfguard.CsrfGuardFilter
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class CsrfGuardControlFilter extends AccessControlFilter {

	CsrfGuardFilter delegate = new CsrfGuardFilter();

	/**
	 * Sets the filter config.
	 *
	 * @param filterConfig the filter config
	 */
	@Override
	public void setFilterConfig(FilterConfig filterConfig) {
		super.setFilterConfig(filterConfig);
		delegate.init(filterConfig);
	}

	/**
	 * Determines whether is access allowed.
	 *
	 * @param request the request
	 * @param response the response
	 * @param mappedValue the mapped value
	 * @return the result
	 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		//maybe the short circuit to disable is set
		return !CsrfGuard.getInstance().isEnabled();
	}

	/**
	 * Determines whether on access denied.
	 *
	 * @param request the request
	 * @param response the response
	 * @return the result
	 * @throws Exception if an error occurs
	 */
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}

	/**
	 * execute Chain.
	 *
	 * @param request the request
	 * @param response the response
	 * @param chain the chain
	 */
	@Override
	public void executeChain(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException( "just supports HTTP requests");
		}

		delegate.doFilter(request, response, chain);

	}

}
