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

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class CsrfguardJavascriptServletProperties {

	private String pattern = "/csrfguard.js";
	private String cacheControl = "private, maxage=28800";
	private boolean domainStrict = true;
	private boolean injectIntoAttributes = true;
	private boolean injectGetForms = true;
	private boolean injectFormAttributes = true;
	private boolean injectIntoForms = true;
	private String refererPattern = ".*";
	private boolean refererMatchDomain = true;
	private String sourceFile = null;
	private String XRequestedWith = "OWASP CSRFGuard Project";

	/**
	 * Returns the pattern.
	 *
	 * @return the pattern
	 */
	public String getPattern() {
		return pattern;
	}

	/**
	 * Sets the pattern.
	 *
	 * @param pattern the pattern
	 */
	public void setPattern(String pattern) {
		this.pattern = pattern;
	}

	/**
	 * Returns the cache control.
	 *
	 * @return the cache control
	 */
	public String getCacheControl() {
		return cacheControl;
	}

	/**
	 * Sets the cache control.
	 *
	 * @param cacheControl the cache control
	 */
	public void setCacheControl(String cacheControl) {
		this.cacheControl = cacheControl;
	}

	/**
	 * Returns the domain strict.
	 *
	 * @return the domain strict
	 */
	public boolean isDomainStrict() {
		return domainStrict;
	}

	/**
	 * Sets the domain strict.
	 *
	 * @param domainStrict the domain strict
	 */
	public void setDomainStrict(boolean domainStrict) {
		this.domainStrict = domainStrict;
	}

	/**
	 * Returns the inject into attributes.
	 *
	 * @return the inject into attributes
	 */
	public boolean isInjectIntoAttributes() {
		return injectIntoAttributes;
	}

	/**
	 * Sets the inject into attributes.
	 *
	 * @param injectIntoAttributes the inject into attributes
	 */
	public void setInjectIntoAttributes(boolean injectIntoAttributes) {
		this.injectIntoAttributes = injectIntoAttributes;
	}

	/**
	 * Returns the inject get forms.
	 *
	 * @return the inject get forms
	 */
	public boolean isInjectGetForms() {
		return injectGetForms;
	}

	/**
	 * Sets the inject get forms.
	 *
	 * @param injectGetForms the inject get forms
	 */
	public void setInjectGetForms(boolean injectGetForms) {
		this.injectGetForms = injectGetForms;
	}

	/**
	 * Returns the inject form attributes.
	 *
	 * @return the inject form attributes
	 */
	public boolean isInjectFormAttributes() {
		return injectFormAttributes;
	}

	/**
	 * Sets the inject form attributes.
	 *
	 * @param injectFormAttributes the inject form attributes
	 */
	public void setInjectFormAttributes(boolean injectFormAttributes) {
		this.injectFormAttributes = injectFormAttributes;
	}

	/**
	 * Returns the inject into forms.
	 *
	 * @return the inject into forms
	 */
	public boolean isInjectIntoForms() {
		return injectIntoForms;
	}

	/**
	 * Sets the inject into forms.
	 *
	 * @param injectIntoForms the inject into forms
	 */
	public void setInjectIntoForms(boolean injectIntoForms) {
		this.injectIntoForms = injectIntoForms;
	}

	/**
	 * Returns the referer pattern.
	 *
	 * @return the referer pattern
	 */
	public String getRefererPattern() {
		return refererPattern;
	}

	/**
	 * Sets the referer pattern.
	 *
	 * @param refererPattern the referer pattern
	 */
	public void setRefererPattern(String refererPattern) {
		this.refererPattern = refererPattern;
	}

	/**
	 * Returns the referer match domain.
	 *
	 * @return the referer match domain
	 */
	public boolean isRefererMatchDomain() {
		return refererMatchDomain;
	}

	/**
	 * Sets the referer match domain.
	 *
	 * @param refererMatchDomain the referer match domain
	 */
	public void setRefererMatchDomain(boolean refererMatchDomain) {
		this.refererMatchDomain = refererMatchDomain;
	}

	/**
	 * Returns the source file.
	 *
	 * @return the source file
	 */
	public String getSourceFile() {
		return sourceFile;
	}

	/**
	 * Sets the source file.
	 *
	 * @param sourceFile the source file
	 */
	public void setSourceFile(String sourceFile) {
		this.sourceFile = sourceFile;
	}

	/**
	 * Returns the x requested with.
	 *
	 * @return the x requested with
	 */
	public String getXRequestedWith() {
		return XRequestedWith;
	}

	/**
	 * Sets the x requested with.
	 *
	 * @param xRequestedWith the x requested with
	 */
	public void setXRequestedWith(String xRequestedWith) {
		XRequestedWith = xRequestedWith;
	}

}
