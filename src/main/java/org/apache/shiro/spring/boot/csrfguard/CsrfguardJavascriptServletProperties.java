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
package org.apache.shiro.spring.boot.csrfguard;

/**
 * TODO
 * @author ： <a href="https://github.com/vindell">vindell</a>
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

	public String getPattern() {
		return pattern;
	}

	public void setPattern(String pattern) {
		this.pattern = pattern;
	}

	public String getCacheControl() {
		return cacheControl;
	}

	public void setCacheControl(String cacheControl) {
		this.cacheControl = cacheControl;
	}

	public boolean isDomainStrict() {
		return domainStrict;
	}

	public void setDomainStrict(boolean domainStrict) {
		this.domainStrict = domainStrict;
	}

	public boolean isInjectIntoAttributes() {
		return injectIntoAttributes;
	}

	public void setInjectIntoAttributes(boolean injectIntoAttributes) {
		this.injectIntoAttributes = injectIntoAttributes;
	}

	public boolean isInjectGetForms() {
		return injectGetForms;
	}

	public void setInjectGetForms(boolean injectGetForms) {
		this.injectGetForms = injectGetForms;
	}

	public boolean isInjectFormAttributes() {
		return injectFormAttributes;
	}

	public void setInjectFormAttributes(boolean injectFormAttributes) {
		this.injectFormAttributes = injectFormAttributes;
	}

	public boolean isInjectIntoForms() {
		return injectIntoForms;
	}

	public void setInjectIntoForms(boolean injectIntoForms) {
		this.injectIntoForms = injectIntoForms;
	}

	public String getRefererPattern() {
		return refererPattern;
	}

	public void setRefererPattern(String refererPattern) {
		this.refererPattern = refererPattern;
	}

	public boolean isRefererMatchDomain() {
		return refererMatchDomain;
	}

	public void setRefererMatchDomain(boolean refererMatchDomain) {
		this.refererMatchDomain = refererMatchDomain;
	}

	public String getSourceFile() {
		return sourceFile;
	}

	public void setSourceFile(String sourceFile) {
		this.sourceFile = sourceFile;
	}

	public String getXRequestedWith() {
		return XRequestedWith;
	}

	public void setXRequestedWith(String xRequestedWith) {
		XRequestedWith = xRequestedWith;
	}

}
