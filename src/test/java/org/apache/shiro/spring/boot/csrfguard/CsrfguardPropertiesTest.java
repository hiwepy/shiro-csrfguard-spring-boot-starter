package org.apache.shiro.spring.boot.csrfguard;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CsrfguardProperties Tests")
class CsrfguardPropertiesTest {

    private Object getField(Object obj, String name) throws Exception {
        java.lang.reflect.Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(obj);
    }

    private void setField(Object obj, String name, Object value) throws Exception {
        java.lang.reflect.Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        CsrfguardProperties props = new CsrfguardProperties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("Default values are correct")
    void testDefaults() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        assertThat(getField(props, "enabled")).isEqualTo(false);
        assertThat(getField(props, "tokenName")).isEqualTo("OWASP_CSRFGUARD");
        assertThat(getField(props, "tokenLength")).isEqualTo(32);
        assertThat(getField(props, "rotateEnabled")).isEqualTo(false);
        assertThat(getField(props, "tokenPerPageEnabled")).isEqualTo(false);
        assertThat(getField(props, "validationWhenNoSessionExists")).isEqualTo(true);
        assertThat(getField(props, "tokenPerPagePrecreateEnabled")).isEqualTo(false);
        assertThat(getField(props, "printConfig")).isEqualTo(false);
        assertThat(getField(props, "prng")).isEqualTo("SHA1PRNG");
        assertThat(getField(props, "prngProvider")).isEqualTo("SUN");
        assertThat(getField(props, "useNewTokenLandingPage")).isEqualTo(false);
        assertThat(getField(props, "ajaxEnabled")).isEqualTo(false);
        assertThat(getField(props, "protectEnabled")).isEqualTo(false);
        assertThat(getField(props, "sessionKey")).isEqualTo("OWASP_CSRFGUARD_KEY");
    }

    @Test
    @DisplayName("Setters work for all fields")
    void testSetters() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "enabled", true);
        assertThat(getField(props, "enabled")).isEqualTo(true);
        setField(props, "tokenName", "TEST");
        assertThat(getField(props, "tokenName")).isEqualTo("TEST");
        setField(props, "tokenLength", 64);
        assertThat(getField(props, "tokenLength")).isEqualTo(64);
    }

    @Test
    @DisplayName("LoggerType enum values")
    void testLoggerType() {
        CsrfguardProperties.LoggerType console = CsrfguardProperties.LoggerType.CONSOLE;
        CsrfguardProperties.LoggerType java = CsrfguardProperties.LoggerType.JAVA;
        assertThat(console.className()).isEqualTo("org.owasp.csrfguard.log.ConsoleLogger");
        assertThat(java.className()).isEqualTo("org.owasp.csrfguard.log.JavaLogger");
        assertThat(console.equals(java)).isFalse();
    }

    @Test
    @DisplayName("toProperties returns correct properties")
    void testToProperties() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "enabled", true);
        setField(props, "tokenName", "TEST_TOKEN");
        setField(props, "newTokenLandingPage", "/");
        Properties result = props.toProperties();
        assertThat(result).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.Enabled")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.TokenName")).isEqualTo("TEST_TOKEN");
        assertThat(result.get("org.owasp.csrfguard.Logger")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.TokenLength")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.Rotate")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.TokenPerPage")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.ValidateWhenNoSessionExists")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.TokenPerPagePrecreate")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.PRNG")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.PRNG.Provider")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.NewTokenLandingPage")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.Config.Print")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.UseNewTokenLandingPage")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.SessionKey")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.Ajax")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.Protect")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.ProtectedMethods")).isNotNull();
        assertThat(result.get("org.owasp.csrfguard.UnprotectedMethods")).isNotNull();
    }

    @Test
    @DisplayName("toProperties with actions")
    void testToPropertiesWithActions() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "newTokenLandingPage", "/");
        Map<String, String> actions = new HashMap<>();
        actions.put("test", "value");
        setField(props, "actions", actions);
        Properties result = props.toProperties();
        assertThat(result.getProperty("org.owasp.csrfguard.action.test")).isEqualTo("value");
    }

    @Test
    @DisplayName("toProperties with protected pages")
    void testToPropertiesWithProtectedPages() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "newTokenLandingPage", "/");
        Map<String, String> pages = new HashMap<>();
        pages.put("/admin", "true");
        setField(props, "protectedPages", pages);
        Properties result = props.toProperties();
        assertThat(result.getProperty("org.owasp.csrfguard.protected./admin")).isEqualTo("true");
    }

    @Test
    @DisplayName("toProperties with unprotected pages")
    void testToPropertiesWithUnprotectedPages() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "newTokenLandingPage", "/");
        Map<String, String> pages = new HashMap<>();
        pages.put("/public", "true");
        setField(props, "unprotectedPages", pages);
        Properties result = props.toProperties();
        assertThat(result.getProperty("org.owasp.csrfguard.unprotected./public")).isEqualTo("true");
    }

    @Test
    @DisplayName("toProperties with protected methods")
    void testToPropertiesWithProtectedMethods() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "newTokenLandingPage", "/");
        Set<String> methods = new HashSet<>();
        methods.add("POST");
        methods.add("PUT");
        setField(props, "protectedMethods", methods);
        Properties result = props.toProperties();
        assertThat(result.getProperty("org.owasp.csrfguard.ProtectedMethods")).contains("POST");
    }

    @Test
    @DisplayName("toProperties with unprotected methods")
    void testToPropertiesWithUnprotectedMethods() throws Exception {
        CsrfguardProperties props = new CsrfguardProperties();
        setField(props, "newTokenLandingPage", "/");
        Set<String> methods = new HashSet<>();
        methods.add("GET");
        setField(props, "unprotectedMethods", methods);
        Properties result = props.toProperties();
        assertThat(result.getProperty("org.owasp.csrfguard.UnprotectedMethods")).contains("GET");
    }
}
