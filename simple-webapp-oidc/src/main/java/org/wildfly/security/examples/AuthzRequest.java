package org.wildfly.security.examples;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.keycloak.adapters.authorization.HttpRequest;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;
import org.wildfly.security.http.oidc.RefreshableOidcSecurityContext;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthzRequest implements HttpRequest {

    private HttpServletRequest request;
    private RefreshableOidcSecurityContext securityContext;

    public AuthzRequest(HttpServletRequest request, RefreshableOidcSecurityContext securityContext) {
        this.request = request;
        this.securityContext = securityContext;
    }

    @Override
    public String getRelativePath() {
        return request.getServletPath();
    }

    @Override
    public String getMethod() {
        return request.getMethod();
    }

    @Override
    public String getUri() {
        return request.getRequestURI();
    }

    @Override
    public boolean isAuthenticated() {
        if (securityContext == null) {
            return false;
        }

        return securityContext.isActive();
    }

    @Override
    public AccessToken getBearerToken() {
        try {
            return new JWSInput(getRawBearerToken()).readJsonContent(AccessToken.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<String> getHeaders(String name) {
        return Collections.list(request.getHeaders(name));
    }

    @Override
    public String getRawBearerToken() {
        return securityContext.getTokenString();
    }

    @Override
    public String getQueryParamValue(String name) {
        return request.getParameter(name);
    }

    @Override
    public String getFirstParam(String name) {
        Map<String, String[]> parameters = request.getParameterMap();
        String[] values = parameters.get(name);

        if (values == null || values.length == 0) {
            return null;
        }

        return values[0];
    }

    @Override
    public String getCookieValue(String name) {
        return null;
    }

    @Override
    public String getRemoteAddr() {
        return null;
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public String getHeader(String name) {
        return null;
    }

    @Override
    public InputStream getInputStream(boolean buffered) {
        return null;
    }
}
