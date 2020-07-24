package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.csrfguard.CsrfguardConstants;
import org.apache.shiro.spring.boot.csrfguard.CsrfguardJavascriptServletProperties;
import org.apache.shiro.spring.boot.csrfguard.web.filter.CsrfGuardFilter;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardHttpSessionListener;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(org.owasp.csrfguard.CsrfGuard.class)
@ConditionalOnProperty(prefix = ShiroCsrfguardProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(ShiroCsrfguardProperties.class)
public class ShiroCsrfguardAutoConfiguration implements ApplicationContextAware {
	
	private ApplicationContext applicationContext;
	
	@Bean
	public CsrfGuard csrfGuard(ShiroCsrfguardProperties properties){
		try {
			CsrfGuard.load(properties.toProperties());
		} catch (Exception e) {
		}
		return CsrfGuard.getInstance();
	}
	
	@Bean
    @ConditionalOnMissingBean
	public ServletRegistrationBean<JavaScriptServlet> javaScriptServlet(ShiroCsrfguardProperties properties) throws Exception {

		ServletRegistrationBean<JavaScriptServlet> registrationBean = new ServletRegistrationBean<JavaScriptServlet>();
        
		JavaScriptServlet javaScriptServlet = new JavaScriptServlet();
		
		registrationBean.setServlet(javaScriptServlet);
		
		// 默认参数
		CsrfguardJavascriptServletProperties javascript = properties.getJavascript();
		registrationBean.addInitParameter(CsrfguardConstants.CACHE_CONTROL_KEY, javascript.getCacheControl());
		registrationBean.addInitParameter(CsrfguardConstants.DOMAIN_STRICT_KEY, Boolean.toString(javascript.isDomainStrict()));
		registrationBean.addInitParameter(CsrfguardConstants.INJECT_FORM_ATTRIBUTES_KEY, Boolean.toString(javascript.isInjectIntoAttributes()));
		registrationBean.addInitParameter(CsrfguardConstants.INJECT_GET_FORMS_KEY, Boolean.toString(javascript.isInjectGetForms()));
		registrationBean.addInitParameter(CsrfguardConstants.INJECT_INTO_ATTRIBUTES_KEY, Boolean.toString(javascript.isInjectFormAttributes()));
		registrationBean.addInitParameter(CsrfguardConstants.INJECT_INTO_FORMS_KEY, Boolean.toString(javascript.isInjectIntoForms()));
		registrationBean.addInitParameter(CsrfguardConstants.REFERER_PATTERN_KEY, javascript.getRefererPattern());
		registrationBean.addInitParameter(CsrfguardConstants.REFERER_MATCH_DOMAIN_KEY, Boolean.toString(javascript.isRefererMatchDomain()));
		registrationBean.addInitParameter(CsrfguardConstants.SOURCE_FILE_KEY, javascript.getSourceFile());
		registrationBean.addInitParameter(CsrfguardConstants.XREQUESTEDWITH_KEY, javascript.getXRequestedWith());
		registrationBean.addUrlMappings(javascript.getPattern());

        return registrationBean;
    }
	
	@Bean
	@ConditionalOnProperty(prefix = "shiro", value = "session-creation-enabled", havingValue = "true")
	protected ServletListenerRegistrationBean<CsrfGuardHttpSessionListener> csrfGuardHttpSessionListener()
			throws Exception {
		
		ServletListenerRegistrationBean<CsrfGuardHttpSessionListener> registration = new ServletListenerRegistrationBean<CsrfGuardHttpSessionListener>();
		registration.setListener(new CsrfGuardHttpSessionListener());
		registration.setOrder(Integer.MIN_VALUE);
		registration.setEnabled(false);
		
		return registration;
	}
	
	@Bean("csrf")
    @ConditionalOnMissingBean(name = "csrf")
    protected FilterRegistrationBean<CsrfGuardFilter> csrfGuardFilter() throws Exception {

        FilterRegistrationBean<CsrfGuardFilter> registration = new FilterRegistrationBean<CsrfGuardFilter>();
        registration.setFilter(new CsrfGuardFilter());
        registration.setOrder(Integer.MIN_VALUE);
        registration.setEnabled(false);
        return registration;
        
    }
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}
	
}
 