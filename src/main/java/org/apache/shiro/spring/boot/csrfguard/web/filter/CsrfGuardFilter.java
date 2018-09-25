/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.web.filter.AccessControlFilter;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.http.InterceptRedirectResponse;

/**                
 * 拷贝 org.owasp.csrfguard.CsrfGuardFilter
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class CsrfGuardFilter extends AccessControlFilter {
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		//maybe the short circuit to disable is set
		return !CsrfGuard.getInstance().isEnabled();
	}  

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		/** only work with HttpServletRequest objects **/
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpSession session = httpRequest.getSession(false);
			
			//if there is no session and we arent validating when no session exists
			if (session == null && !CsrfGuard.getInstance().isValidateWhenNoSessionExists()) {
				// If there is no session, no harm can be done
				return true;
			}

			CsrfGuard csrfGuard = CsrfGuard.getInstance();
			csrfGuard.getLogger().log(String.format("CsrfGuard analyzing request %s", httpRequest.getRequestURI()));

			InterceptRedirectResponse httpResponse = new InterceptRedirectResponse((HttpServletResponse) response, httpRequest, csrfGuard);

//			 if(MultipartHttpServletRequest.isMultipartRequest(httpRequest)) {
//				 httpRequest = new MultipartHttpServletRequest(httpRequest);
//			 }

			if ((session != null && session.isNew()) && csrfGuard.isUseNewTokenLandingPage()) {
				csrfGuard.writeLandingPage(httpRequest, httpResponse);
			} else if (csrfGuard.isValidRequest(httpRequest, httpResponse)) {
				return true;
			} else {
				/** invalid request - nothing to do - actions already executed **/
			}

			/** update tokens **/
			csrfGuard.updateTokens(httpRequest);

		} else {
			filterConfig.getServletContext().log(String.format("[WARNING] CsrfGuard does not know how to work with requests of class %s ", request.getClass().getName()));
			return true;
		}
		
		return true;
	}
	
}
