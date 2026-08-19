package org.apache.shiro.spring.boot;

import java.lang.reflect.Method;

import org.apache.shiro.spring.boot.csrfguard.CsrfguardConstants;
import org.apache.shiro.spring.boot.csrfguard.CsrfguardJavascriptServletProperties;
import org.apache.shiro.spring.boot.csrfguard.web.filter.CsrfGuardControlFilter;
import org.apache.shiro.spring.boot.utils.JakartaFilterAdapter;
import org.apache.shiro.spring.boot.utils.JakartaServletAdapter;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardHttpSessionListener;
import org.owasp.csrfguard.CsrfGuardServletContextListener;
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
/**
 * Auto-configuration for Shiro CSRF Guard integration.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class ShiroCsrfguardAutoConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	/**
	 * csrf Guard.
	 *
	 * @param properties the properties
	 * @return the result
	 */
	@Bean
	public CsrfGuard csrfGuard(ShiroCsrfguardProperties properties){
		try {
			CsrfGuard.load(properties.toProperties());
		} catch (Exception e) {
		}
		return CsrfGuard.getInstance();
	}

	/**
	 * java Script Servlet.
	 *
	 * @param properties the properties
	 * @return the result
	 * @throws Exception if an error occurs
	 */
	@Bean
    @ConditionalOnMissingBean
	public ServletRegistrationBean<jakarta.servlet.Servlet> javaScriptServlet(ShiroCsrfguardProperties properties) throws Exception {

		JavaScriptServlet javaScriptServlet = new JavaScriptServlet();
		// Wrap javax.servlet.http.HttpServlet as jakarta.servlet.Servlet
		ServletRegistrationBean<jakarta.servlet.Servlet> registrationBean =
				new ServletRegistrationBean<>(new JakartaServletAdapter(javaScriptServlet));

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

	/**
	 * csrf Guard HTTP Session Listener.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnProperty(prefix = "shiro", value = "session-creation-enabled", havingValue = "true")
	protected ServletListenerRegistrationBean<jakarta.servlet.http.HttpSessionListener> csrfGuardHttpSessionListener()
			throws Exception {

		// Use a jakarta HttpSessionListener adapter since CsrfGuardHttpSessionListener implements javax
		jakarta.servlet.http.HttpSessionListener jakartaListener = createJakartaSessionListener();
		ServletListenerRegistrationBean<jakarta.servlet.http.HttpSessionListener> registration =
				new ServletListenerRegistrationBean<>(jakartaListener);
		registration.setOrder(Integer.MIN_VALUE);
		registration.setEnabled(false);

		return registration;
	}

	private jakarta.servlet.http.HttpSessionListener createJakartaSessionListener() {
		CsrfGuardHttpSessionListener javaxListener = new CsrfGuardHttpSessionListener();
		return new jakarta.servlet.http.HttpSessionListener() {
			/**
			 * session Created.
			 *
			 * @param se the se
			 */
			@Override
			public void sessionCreated(jakarta.servlet.http.HttpSessionEvent se) {
				try {
					Class<?> eventClass = Class.forName("javax.servlet.http.HttpSessionEvent");
					Object javaxEvent = adaptSessionEvent(se, eventClass);
					javaxListener.getClass().getMethod("sessionCreated", eventClass).invoke(javaxListener, javaxEvent);
				} catch (Exception e) {
					// ignore
				}
			}

			/**
			 * session Destroyed.
			 *
			 * @param se the se
			 */
			@Override
			public void sessionDestroyed(jakarta.servlet.http.HttpSessionEvent se) {
				try {
					Class<?> eventClass = Class.forName("javax.servlet.http.HttpSessionEvent");
					Object javaxEvent = adaptSessionEvent(se, eventClass);
					javaxListener.getClass().getMethod("sessionDestroyed", eventClass).invoke(javaxListener, javaxEvent);
				} catch (Exception e) {
					// ignore
				}
			}

			private Object adaptSessionEvent(jakarta.servlet.http.HttpSessionEvent se, Class<?> javaxEventClass) throws Exception {
				return java.lang.reflect.Proxy.newProxyInstance(
						javaxEventClass.getClassLoader(),
						new Class<?>[]{javaxEventClass},
						(proxy, method, args) -> {
							Method jakartaMethod = se.getClass().getMethod(method.getName(), method.getParameterTypes());
							return jakartaMethod.invoke(se, args);
						}
				);
			}
		};
	}

    /**
     * csrf Guard Filter.
     *
     * @return the result
     * @throws Exception if an error occurs
     */
	@Bean("csrf")
    @ConditionalOnMissingBean(name = "csrf")
    protected FilterRegistrationBean<jakarta.servlet.Filter> csrfGuardFilter() throws Exception {

        FilterRegistrationBean<jakarta.servlet.Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new JakartaFilterAdapter(new CsrfGuardControlFilter()));
        registration.setOrder(Integer.MIN_VALUE);
        registration.setEnabled(false);
        return registration;

    }

	/**
	 * csrf Guard Servlet Context Listener.
	 *
	 * @return the result
	 */
	@Bean
	protected CsrfGuardServletContextListener csrfGuardServletContextListener() {
		return new CsrfGuardServletContextListener();
	}

	/**
	 * Sets the application context.
	 *
	 * @param applicationContext the application context
	 * @throws BeansException if an error occurs
	 */
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	/**
	 * Returns the application context.
	 *
	 * @return the application context
	 */
	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
