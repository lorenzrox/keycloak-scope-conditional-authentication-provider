package org.keycloak.authentication.authenticators.conditional;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.rar.AuthorizationDetails;
import org.keycloak.services.util.AuthorizationContextUtil;
import org.keycloak.sessions.AuthenticationSessionModel;

public class ConditionalScopeAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalScopeAuthenticator SINGLETON = new ConditionalScopeAuthenticator();

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        boolean negateOutput = Boolean.parseBoolean(config.get(ConditionalUserAttributeValueFactory.CONF_NOT));
        boolean regexOutput = Boolean.parseBoolean(config.get(ConditionalUserAttributeValueFactory.REGEX));
        String scopeName = config.get(ConditionalScopeAuthenticatorFactory.SCOPE);

        List<AuthorizationDetails> scopes = getClientScopeModelStream(context).collect(Collectors.toList());
        if (regexOutput) {
            return matchUsingRegex(scopes, scopeName) ^ negateOutput;
        } else {
            return matchSimple(scopes, scopeName) ^ negateOutput;
        }
    }

    private static boolean matchSimple(List<AuthorizationDetails> scopes, String scopeName) {
        if (scopeName == null || scopeName.isEmpty() || scopes == null || scopes.isEmpty()) {
            return false;
        }

        for (AuthorizationDetails scope : scopes) {
            if (scope.isDynamicScope()) {
                if (Objects.equals(scope.getClientScope().getName() + ":" + scope.getDynamicScopeParam(), scopeName)) {
                    return true;
                }
            } else if (Objects.equals(scope.getClientScope().getName(), scopeName)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchUsingRegex(List<AuthorizationDetails> scopes, String scopeName) {
        if (scopeName == null || scopeName.isEmpty() || scopes == null || scopes.isEmpty()) {
            return false;
        }

        Pattern pattern = Pattern.compile(scopeName, Pattern.DOTALL);

        for (AuthorizationDetails scope : scopes) {
            if (scope.isDynamicScope()) {
                if (pattern.matcher(scope.getClientScope().getName() + ":" + scope.getDynamicScopeParam()).matches()) {
                    return true;
                }
            } else if (pattern.matcher(scope.getClientScope().getName()).matches()) {
                return true;
            }
        }

        return false;
    }

    private static Stream<AuthorizationDetails> getClientScopeModelStream(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        // if Dynamic Scopes are enabled, get the scopes from the
        // AuthorizationRequestContext, passing the session and scopes as parameters
        // then concat a Stream with the ClientModel, as it's discarded in the
        // getAuthorizationRequestContext method
        if (Profile.isFeatureEnabled(Profile.Feature.DYNAMIC_SCOPES)) {
            return AuthorizationContextUtil.getAuthorizationRequestsStreamFromScopesWithClient(context.getSession(),
                    authSession.getClientNote(OAuth2Constants.SCOPE));
        }
        // if dynamic scopes are not enabled, we retain the old behaviour, but the
        // ClientScopes will be wrapped in
        // AuthorizationRequest objects to standardize the code handling these.
        return authSession.getClientScopes().stream()
                .map(scopeId -> KeycloakModelUtils.findClientScopeById(authSession.getRealm(), authSession.getClient(),
                        scopeId))
                .map(AuthorizationDetails::new);
    }

    @Override
    public void close() {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }
}
