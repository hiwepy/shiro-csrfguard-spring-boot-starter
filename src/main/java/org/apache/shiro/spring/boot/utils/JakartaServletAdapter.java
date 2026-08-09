package org.apache.shiro.spring.boot.utils;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.reflect.Method;

/**
 * Adapter that bridges a {@code javax.servlet.http.HttpServlet} to a {@code jakarta.servlet.Servlet}.
 * <p>CSRF Guard's JavaScriptServlet extends {@code javax.servlet.http.HttpServlet} while
 * Spring Boot 4.x's {@code ServletRegistrationBean} requires {@code jakarta.servlet.Servlet}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class JakartaServletAdapter implements Servlet {

    private final Object delegate;

    public JakartaServletAdapter(Object delegate) {
        this.delegate = delegate;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        try {
            Class<?> javaxConfigClass = Class.forName("javax.servlet.ServletConfig");
            Method initMethod = delegate.getClass().getMethod("init", javaxConfigClass);
            initMethod.invoke(delegate, adaptConfig(config));
        } catch (Exception e) {
            throw new ServletException("Failed to init delegate servlet", e);
        }
    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        try {
            Class<?> javaxRequestClass = Class.forName("javax.servlet.ServletRequest");
            Class<?> javaxResponseClass = Class.forName("javax.servlet.ServletResponse");
            Method serviceMethod = delegate.getClass().getMethod("service", javaxRequestClass, javaxResponseClass);
            serviceMethod.invoke(delegate, req, res);
        } catch (Exception e) {
            throw new ServletException("Failed to invoke service on delegate", e);
        }
    }

    @Override
    public String getServletInfo() {
        return "JakartaServletAdapter wrapping: " + delegate.getClass().getName();
    }

    @Override
    public void destroy() {
        try {
            Method destroyMethod = delegate.getClass().getMethod("destroy");
            destroyMethod.invoke(delegate);
        } catch (Exception e) {
            // ignore
        }
    }

    private Object adaptConfig(ServletConfig jakartaConfig) throws Exception {
        Class<?> javaxConfigClass = Class.forName("javax.servlet.ServletConfig");
        return java.lang.reflect.Proxy.newProxyInstance(
                javaxConfigClass.getClassLoader(),
                new Class<?>[]{javaxConfigClass},
                (proxy, method, args) -> {
                    // Delegate all methods to the jakarta config
                    Method jakartaMethod = jakartaConfig.getClass().getMethod(method.getName(), method.getParameterTypes());
                    return jakartaMethod.invoke(jakartaConfig, args);
                }
        );
    }
}
