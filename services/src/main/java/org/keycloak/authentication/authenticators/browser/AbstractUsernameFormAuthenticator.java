/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AbstractFormAuthenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class AbstractUsernameFormAuthenticator extends AbstractFormAuthenticator {

    private static final Logger logger = Logger.getLogger(AbstractUsernameFormAuthenticator.class);

    public static final String REGISTRATION_FORM_ACTION = "registration_form";
    public static final String ATTEMPTED_USERNAME = "ATTEMPTED_USERNAME";

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    protected Response challenge(AuthenticationFlowContext context, String error) {
        LoginFormsProvider form = context.form()
                .setAuthContext(context)
                .setExecution(context.getExecution().getId());
        if (error != null) form.setError(error);
        return createLoginForm(form);
    }

    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsernamePassword();
    }

    protected String tempDisabledError() {
        return Messages.INVALID_USER;
    }

    protected Response setDuplicateUserChallenge(AuthenticationFlowContext context, String eventError, String loginFormError, AuthenticationFlowError authenticatorError) {
        context.getEvent().error(eventError);
        Response challengeResponse = context.form().setAuthContext(context)
                .setError(loginFormError).createLoginUsernamePassword();
        context.failureChallenge(authenticatorError, challengeResponse);
        return challengeResponse;
    }

    protected void runDefaultDummyHash(AuthenticationFlowContext context) {
        PasswordHashProvider hash = context.getSession().getProvider(PasswordHashProvider.class, PasswordPolicy.HASH_ALGORITHM_DEFAULT);
        hash.encode("dummypassword", PasswordPolicy.HASH_ITERATIONS_DEFAULT);
    }

    protected void dummyHash(AuthenticationFlowContext context) {
        PasswordPolicy policy = context.getRealm().getPasswordPolicy();
        if (policy == null) {
            runDefaultDummyHash(context);
            return;
        } else {
            PasswordHashProvider hash = context.getSession().getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
            if (hash == null) {
                runDefaultDummyHash(context);
                return;

            } else {
                hash.encode("dummypassword", policy.getHashIterations());
            }
        }

    }

    public boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            dummyHash(context);
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return true;
        }
        return false;
    }


    public boolean enabledUser(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            Response challengeResponse = challenge(context, Messages.ACCOUNT_DISABLED);
            context.forceChallenge(challengeResponse);
            return false;
        }
        if (isTemporarilyDisabledByBruteForce(context, user)) return false;
        return true;
    }

    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData)  {
        UserModel user = validateUser(context, inputData);
        return user != null && validatePassword(context, user, inputData) && context.getUser() != null;
    }


    public UserModel validateUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        context.clearUser();
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }

            return user;
        }

        if (invalidUser(context, user) || !enabledUser(context, user)) {
            return user;
        }

        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);
        return user;
    }


    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        return validatePassword(context, user, inputData, true);
    }

    public boolean validatePassword(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = inputData.getFirst(CredentialRepresentation.PASSWORD);

        if (isTemporarilyDisabledByBruteForce(context, user)) return false;

        if (password != null && !password.isEmpty() && context.getSession().userCredentialManager().isValid(context.getRealm(), user, UserCredentialModel.password(password))) {
            return true;
        } else {
            context.getEvent().user(user);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, Messages.INVALID_USER);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            if (clearUser) {
                context.clearUser();
            }
            return false;
        }
    }


    protected boolean isTemporarilyDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
        if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                context.getEvent().user(user);
                context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                Response challengeResponse = challenge(context, tempDisabledError());
                context.forceChallenge(challengeResponse);
                return true;
            }
        }
        return false;
    }
}
