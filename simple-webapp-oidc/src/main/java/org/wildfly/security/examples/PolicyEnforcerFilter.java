package org.wildfly.security.examples;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContextAttributeEvent;
import jakarta.servlet.ServletContextAttributeListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.keycloak.AuthorizationContext;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.authorization.client.ClientAuthenticator;
import org.wildfly.security.http.oidc.ClientCredentialsProviderUtils;
import org.wildfly.security.http.oidc.Oidc;
import org.wildfly.security.http.oidc.OidcClientConfiguration;
import org.wildfly.security.http.oidc.OidcClientContext;
import org.wildfly.security.http.oidc.OidcSecurityContext;
import org.wildfly.security.http.oidc.RefreshableOidcSecurityContext;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEnforcerFilter implements Filter, ServletContextAttributeListener {

    private PolicyEnforcer policyEnforcer;

    @Override
    public void attributeAdded(ServletContextAttributeEvent event) {
        ServletContextAttributeListener.super.attributeAdded(event);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        OidcClientContext oidcContext = (OidcClientContext) filterConfig.getServletContext().getAttribute(Oidc.OIDC_CLIENT_CONTEXT_KEY);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpSession session = request.getSession(false);

        if (session == null) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        RefreshableOidcSecurityContext securityContext = (RefreshableOidcSecurityContext) session.getAttribute(OidcSecurityContext.class.getName());
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        PolicyEnforcer policyEnforcer = getOrCreatePolicyEnforcer(request, securityContext);
        AuthorizationContext authzContext = policyEnforcer.enforce(new AuthzRequest(request, securityContext), new AuthzResponse(response));

        if (authzContext.isGranted()) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private synchronized PolicyEnforcer getOrCreatePolicyEnforcer(HttpServletRequest request, RefreshableOidcSecurityContext securityContext) {
        if (policyEnforcer == null) {
            InputStream enforcerConfig = request.getServletContext().getResourceAsStream("WEB-INF/policy-enforcer.json");
            OidcClientConfiguration configuration = securityContext.getOidcClientConfiguration();
            String authServerUrl = configuration.getProviderUrl().substring(0, configuration.getProviderUrl().indexOf("/realms"));
            return policyEnforcer = PolicyEnforcer.builder()
                    .authServerUrl(authServerUrl)
                    .realm(configuration.getRealm())
                    .clientId(configuration.getClientId())
                    .credentials(configuration.getResourceCredentials())
                    .bearerOnly(false)
                    .clientAuthenticator(new ClientAuthenticator() {
                        @Override
                        public void configureClientCredentials(Map<String, List<String>> requestParams, Map<String, String> requestHeaders) {
                            HashMap<String, String> authHeaders = new HashMap<>();
                            HashMap<String, String> authParams = new HashMap<>();

                            ClientCredentialsProviderUtils.setClientCredentials(configuration, authHeaders, authParams);

                            requestHeaders.putAll(authHeaders);

                            for (Entry<String, String> entry : authParams.entrySet()) {
                                requestParams.put(entry.getKey(), List.of(entry.getValue()));
                            }
                        }
                    })
                    .enforcerConfig(enforcerConfig)
                    .httpClient(configuration.getClient()).build();
        }

        return policyEnforcer;
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
