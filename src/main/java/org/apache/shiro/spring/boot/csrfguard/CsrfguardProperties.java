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
package org.apache.shiro.spring.boot.csrfguard;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.biz.utils.StringUtils;

/**
 * TODO
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class CsrfguardProperties {

	private final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";

	private final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";

	private final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

	public enum LoggerType {

		CONSOLE("org.owasp.csrfguard.log.ConsoleLogger"), 
		JAVA("org.owasp.csrfguard.log.JavaLogger");

		private final String implClassName;

		LoggerType(String implClassName) {
			this.implClassName = implClassName;
		}

		public String className() {
			return implClassName;
		}

		public boolean equals(LoggerType loggerType) {
			return this.compareTo(loggerType) == 0;
		}

	}

	private boolean enabled = false;
	private LoggerType logger = LoggerType.CONSOLE;
	private String tokenName = "OWASP_CSRFGUARD";
	private int tokenLength = 32;
	private boolean rotateEnabled = false;
	private boolean tokenPerPageEnabled = false;
	/**
	 * If csrf guard filter should check even if there is no session for the user
	 * Note: this changed in 2014/04, the default behavior used to be to not check
	 * if there is no session. If you want the legacy behavior (if your app is not
	 * susceptible to CSRF if the user has no session), set this to false
	 */
	private boolean validationWhenNoSessionExists = true;

	private boolean tokenPerPagePrecreateEnabled = false;
	private boolean printConfig = false;
	private String prng = "SHA1PRNG";
	private String prngProvider = "SUN";

	private String newTokenLandingPage;

	private boolean useNewTokenLandingPage = false;

	private boolean ajaxEnabled = false;

	private boolean protectEnabled = false;

	private String sessionKey = "OWASP_CSRFGUARD_KEY";

	private Map<String, String> actions = new HashMap<String, String>();

	private Map<String, String> protectedPages = new HashMap<String, String>();

	private Map<String, String> unprotectedPages = new HashMap<String, String>();

	private Set<String> protectedMethods = new HashSet<String>();

	private Set<String> unprotectedMethods = new HashSet<String>();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public LoggerType getLogger() {
		return logger;
	}

	public void setLogger(LoggerType logger) {
		this.logger = logger;
	}

	public String getTokenName() {
		return tokenName;
	}

	public void setTokenName(String tokenName) {
		this.tokenName = tokenName;
	}

	public int getTokenLength() {
		return tokenLength;
	}

	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	public boolean isRotateEnabled() {
		return rotateEnabled;
	}

	public void setRotateEnabled(boolean rotateEnabled) {
		this.rotateEnabled = rotateEnabled;
	}

	public boolean isTokenPerPageEnabled() {
		return tokenPerPageEnabled;
	}

	public void setTokenPerPageEnabled(boolean tokenPerPageEnabled) {
		this.tokenPerPageEnabled = tokenPerPageEnabled;
	}

	public boolean isValidationWhenNoSessionExists() {
		return validationWhenNoSessionExists;
	}

	public void setValidationWhenNoSessionExists(boolean validationWhenNoSessionExists) {
		this.validationWhenNoSessionExists = validationWhenNoSessionExists;
	}

	public boolean isTokenPerPagePrecreateEnabled() {
		return tokenPerPagePrecreateEnabled;
	}

	public void setTokenPerPagePrecreateEnabled(boolean tokenPerPagePrecreateEnabled) {
		this.tokenPerPagePrecreateEnabled = tokenPerPagePrecreateEnabled;
	}

	public boolean isPrintConfig() {
		return printConfig;
	}

	public void setPrintConfig(boolean printConfig) {
		this.printConfig = printConfig;
	}

	public String getPrng() {
		return prng;
	}

	public void setPrng(String prng) {
		this.prng = prng;
	}

	public String getPrngProvider() {
		return prngProvider;
	}

	public void setPrngProvider(String prngProvider) {
		this.prngProvider = prngProvider;
	}

	public String getNewTokenLandingPage() {
		return newTokenLandingPage;
	}

	public void setNewTokenLandingPage(String newTokenLandingPage) {
		this.newTokenLandingPage = newTokenLandingPage;
	}

	public boolean isUseNewTokenLandingPage() {
		return useNewTokenLandingPage;
	}

	public void setUseNewTokenLandingPage(boolean useNewTokenLandingPage) {
		this.useNewTokenLandingPage = useNewTokenLandingPage;
	}

	public boolean isAjaxEnabled() {
		return ajaxEnabled;
	}

	public void setAjaxEnabled(boolean ajaxEnabled) {
		this.ajaxEnabled = ajaxEnabled;
	}

	public boolean isProtectEnabled() {
		return protectEnabled;
	}

	public void setProtectEnabled(boolean protectEnabled) {
		this.protectEnabled = protectEnabled;
	}

	public String getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}

	public Map<String, String> getActions() {
		return actions;
	}

	public void setActions(Map<String, String> actions) {
		this.actions = actions;
	}

	public Map<String, String> getProtectedPages() {
		return protectedPages;
	}

	public void setProtectedPages(Map<String, String> protectedPages) {
		this.protectedPages = protectedPages;
	}

	public Map<String, String> getUnprotectedPages() {
		return unprotectedPages;
	}

	public void setUnprotectedPages(Map<String, String> unprotectedPages) {
		this.unprotectedPages = unprotectedPages;
	}

	public Set<String> getProtectedMethods() {
		return protectedMethods;
	}

	public void setProtectedMethods(Set<String> protectedMethods) {
		this.protectedMethods = protectedMethods;
	}

	public Set<String> getUnprotectedMethods() {
		return unprotectedMethods;
	}

	public void setUnprotectedMethods(Set<String> unprotectedMethods) {
		this.unprotectedMethods = unprotectedMethods;
	}

	public Properties toProperties() {

		Properties properties = new Properties();

		properties.put("org.owasp.csrfguard.Logger", logger.className());
		properties.put("org.owasp.csrfguard.TokenName", tokenName);
		properties.put("org.owasp.csrfguard.TokenLength", tokenLength);
		properties.put("org.owasp.csrfguard.Rotate", rotateEnabled);
		properties.put("org.owasp.csrfguard.TokenPerPage", tokenPerPageEnabled);
		properties.put("org.owasp.csrfguard.ValidateWhenNoSessionExists", validationWhenNoSessionExists);
		properties.put("org.owasp.csrfguard.TokenPerPagePrecreate", tokenPerPagePrecreateEnabled);
		properties.put("org.owasp.csrfguard.PRNG", prng);
		properties.put("org.owasp.csrfguard.PRNG.Provider", prngProvider);
		properties.put("org.owasp.csrfguard.NewTokenLandingPage", newTokenLandingPage);
		properties.put("org.owasp.csrfguard.Config.Print", printConfig);
		properties.put("org.owasp.csrfguard.Enabled", enabled);
		properties.put("org.owasp.csrfguard.UseNewTokenLandingPage", useNewTokenLandingPage);
		properties.put("org.owasp.csrfguard.SessionKey", sessionKey);
		properties.put("org.owasp.csrfguard.Ajax", ajaxEnabled);
		properties.put("org.owasp.csrfguard.Protect", protectEnabled);
		properties.put("org.owasp.csrfguard.ProtectedMethods", StringUtils.join(protectedMethods, ","));
		properties.put("org.owasp.csrfguard.UnprotectedMethods", StringUtils.join(unprotectedMethods, ","));
		
		if(MapUtils.isNotEmpty(actions)) {
			Iterator<String> ite = actions.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(ACTION_PREFIX + key, actions.get(key));
			}
		}

		if(MapUtils.isNotEmpty(protectedPages)) {
			Iterator<String> ite = protectedPages.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(PROTECTED_PAGE_PREFIX + key, protectedPages.get(key));
			}
		}
		
		if(MapUtils.isNotEmpty(unprotectedPages)) {
			Iterator<String> ite = unprotectedPages.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(UNPROTECTED_PAGE_PREFIX + key, unprotectedPages.get(key));
			}
		}

		return properties;
	}

}
