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
package org.apache.shiro.spring.boot;

import java.util.Properties;

import org.apache.shiro.spring.boot.csrfguard.CsrfguardJavascriptServletProperties;
import org.apache.shiro.spring.boot.csrfguard.CsrfguardProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;


@ConfigurationProperties(ShiroCsrfguardProperties.PREFIX)
public class ShiroCsrfguardProperties extends CsrfguardProperties {

	public static final String PREFIX = "shiro.csrfguard";
	
	@NestedConfigurationProperty
	private CsrfguardJavascriptServletProperties javascript = new CsrfguardJavascriptServletProperties();

	@Override
	public Properties toProperties() {
		
		Properties properties = super.toProperties();
		properties.put("org.owasp.csrfguard.JavascriptServlet.cacheControl", javascript.getCacheControl());
		properties.put("org.owasp.csrfguard.JavascriptServlet.domainStrict", javascript.isDomainStrict());
		properties.put("org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes", javascript.isInjectIntoAttributes());
		properties.put("org.owasp.csrfguard.JavascriptServlet.injectGetForms", javascript.isInjectGetForms());
		properties.put("org.owasp.csrfguard.JavascriptServlet.injectFormAttributes", javascript.isInjectFormAttributes());
		properties.put("org.owasp.csrfguard.JavascriptServlet.injectIntoForms", javascript.isInjectIntoForms());
		properties.put("org.owasp.csrfguard.JavascriptServlet.refererPattern", javascript.getRefererPattern());
		properties.put("org.owasp.csrfguard.JavascriptServlet.refererMatchDomain", javascript.isRefererMatchDomain());
		properties.put("org.owasp.csrfguard.JavascriptServlet.sourceFile", javascript.getSourceFile());
		properties.put("org.owasp.csrfguard.JavascriptServlet.xRequestedWith", javascript.getXRequestedWith());
		
		return properties;
	}
	
	public CsrfguardJavascriptServletProperties getJavascript() {
		return javascript;
	}

	public void setJavascript(CsrfguardJavascriptServletProperties javascript) {
		this.javascript = javascript;
	}
	
}
