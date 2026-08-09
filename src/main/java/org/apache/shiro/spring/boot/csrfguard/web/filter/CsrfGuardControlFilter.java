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
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class CsrfGuardControlFilter extends AccessControlFilter {

	CsrfGuardFilter delegate = new CsrfGuardFilter();

	@Override
	public void setFilterConfig(FilterConfig filterConfig) {
		super.setFilterConfig(filterConfig);
		delegate.init(filterConfig);
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		//maybe the short circuit to disable is set
		return !CsrfGuard.getInstance().isEnabled();
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}

	@Override
	public void executeChain(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException( "just supports HTTP requests");
		}

		delegate.doFilter(request, response, chain);

	}

}
