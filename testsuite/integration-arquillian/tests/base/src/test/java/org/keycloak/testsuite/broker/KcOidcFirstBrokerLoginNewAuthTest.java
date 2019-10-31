package org.keycloak.testsuite.broker;

import java.util.List;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.broker.IdpAutoLinkAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.PasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.AuthenticationManagementResource;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.PasswordPage;
import org.keycloak.testsuite.runonserver.RunOnServer;
import org.keycloak.testsuite.util.UserBuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

/**
 * Tests first-broker-login flow with new authenticators.
 *
 * Especially for re-authentication of user, which is linking to IDP broker, it uses "Password Form" authenticator instead of default IdpUsernamePasswordForm.
 * It tests various variants with OTP( Conditional OTP, Password-or-OTP) .
 *
 * TODO: in latest master, the KcOidcBrokerTest is final class. This class will need to be changed to extend from AbstractBrokerTest
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KcOidcFirstBrokerLoginNewAuthTest extends KcOidcBrokerTest {

    @Page
    PasswordPage passwordPage;


    // TODO: This can be uncommented once we rebase to latest master and there won't be a need to explicitly call it before each method declared on this class
    // @Before
    public void disableReviewProfileBeforeTest() {
        updateExecutions(AbstractBrokerTest::disableUpdateProfileOnFirstLogin);
    }

    /**
     * Tests the firstBrokerLogin flow configured to re-authenticate with PasswordForm authenticator (Not the form with username/password, but password only)
     * OTP is not configured for the user and hence not requested (There is default OTP conditional subflow used)
     */
    @Test
    public void testReAuthenticateWithPasswordAndConditionalOTP_otpNotRequested() {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        testingClient.server(bc.consumerRealmName()).run(configureBrokerFlowToReAuthenticationWithPasswordForm(bc.getIDPAlias(), "first broker login with password form"));

        String consumerRealmUserId = createUser("consumer");
        loginWithBrokerAndConfirmLinkAccount();

        // Assert on the page with password form
        Assert.assertTrue(passwordPage.isCurrent("consumer"));

        // Try bad password first
        passwordPage.login("bad-password");
        Assert.assertEquals("Invalid username or password.", passwordPage.getError());

        // Try good password
        passwordPage.login("password");

        assertUserAuthenticatedInConsumer(consumerRealmUserId);
    }


    /**
     * Tests the firstBrokerLogin flow configured to re-authenticate with PasswordForm authenticator.
     * Assert that OTP is required too as it is configured for the user (There is default OTP conditional subflow used)
     */
    @Test
    public void testReAuthenticateWithPasswordAndConditionalOTP_otpRequested() {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        testingClient.server(bc.consumerRealmName()).run(configureBrokerFlowToReAuthenticationWithPasswordForm(bc.getIDPAlias(), "first broker login with password form"));

        // Create user and link him with TOTP
        String consumerRealmUserId = createUser("consumer");
        String totpSecret = addTOTPToUser("consumer");

        loginWithBrokerAndConfirmLinkAccount();

        // Login with password
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.login("password");

        // Assert on TOTP page. Login with TOTP
        loginTotpPage.assertCurrent();
        loginTotpPage.login(totp.generateTOTP(totpSecret));

        assertUserAuthenticatedInConsumer(consumerRealmUserId);
    }


    /**
     * Tests the firstBrokerLogin flow configured to re-authenticate with PasswordForm OR TOTP.
     * TOTP is not configured for the user and hence he MUST authenticate with password
     */
    @Test
    public void testReAuthenticateWithPasswordOrOTP_otpNotConfigured_passwordUsed() {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        testingClient.server(bc.consumerRealmName()).run(configureBrokerFlowToReAuthenticationWithPasswordOrTotp(bc.getIDPAlias(), "first broker login with password or totp"));

        String consumerRealmUserId = createUser("consumer");

        loginWithBrokerAndConfirmLinkAccount();

        // Assert that user can't see credentials combobox. Password is the only available credentials.
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.assertCredentialsComboboxAvailability(false);

        // Login with password
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.login("password");

        assertUserAuthenticatedInConsumer(consumerRealmUserId);
    }


    /**
     * Tests the firstBrokerLogin flow configured to re-authenticate with PasswordForm OR TOTP.
     * TOTP is configured for the user and hence he can authenticate with OTP. However he selects password
     */
    @Test
    public void testReAuthenticateWithPasswordOrOTP_otpConfigured_passwordUsed() {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        testingClient.server(bc.consumerRealmName()).run(configureBrokerFlowToReAuthenticationWithPasswordOrTotp(bc.getIDPAlias(), "first broker login with password or totp"));

        // Create user and link him with TOTP
        String consumerRealmUserId = createUser("consumer");
        String totpSecret = addTOTPToUser("consumer");

        loginWithBrokerAndConfirmLinkAccount();

        // Assert that user can see credentials combobox. Password and OTP are available credentials. Password should be selected.
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.assertCredentialsComboboxAvailability(true);
        Assert.assertNames(passwordPage.getAvailableCredentials(), "Password", "OTP");
        Assert.assertEquals("Password", passwordPage.getSelectedCredential());

        // Login with password
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.login("password");

        assertUserAuthenticatedInConsumer(consumerRealmUserId);
    }


    @Test
    public void testReAuthenticateWithPasswordOrOTP_otpConfigured_otpUsed() {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        testingClient.server(bc.consumerRealmName()).run(configureBrokerFlowToReAuthenticationWithPasswordOrTotp(bc.getIDPAlias(), "first broker login with password or totp"));

        // Create user and link him with TOTP
        String consumerRealmUserId = createUser("consumer");
        String totpSecret = addTOTPToUser("consumer");

        loginWithBrokerAndConfirmLinkAccount();

        // Assert that user can see credentials combobox. Password and OTP are available credentials. Password should be selected.
        Assert.assertTrue(passwordPage.isCurrent("consumer"));
        passwordPage.assertCredentialsComboboxAvailability(true);

        // Select OTP and assert
        passwordPage.selectCredential("OTP");
        loginTotpPage.assertCurrent();
        Assert.assertEquals("OTP", loginTotpPage.getSelectedCredential());

        // Login with OTP now
        loginTotpPage.login(totp.generateTOTP(totpSecret));

        assertUserAuthenticatedInConsumer(consumerRealmUserId);
    }



    // Add OTP to the user. Return TOTP secret
    private String addTOTPToUser(String username) {
        // TODO: Change disableReviewProfileBeforeTest() to default method and remove this
        disableReviewProfileBeforeTest();

        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        UserResource user = ApiUtil.findUserByUsernameId(realm, username);

        // Add CONFIGURE_TOTP requiredAction to the user
        UserRepresentation userRep = UserBuilder.edit(user.toRepresentation()).requiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.toString()).build();
        user.update(userRep);

        // Login. TOTP will be required at login time.
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));
        accountLoginPage.login(username, "password");

        totpPage.assertCurrent();
        String totpSecret = totpPage.getTotpSecret();
        totpPage.configure(totp.generateTOTP(totpSecret));

        // Logout user through admin endpoint
        user.logout();

        return totpSecret;
    }


    // Login with broker and click "Link account"
    private void loginWithBrokerAndConfirmLinkAccount() {
        driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

        logInWithBroker(bc);

        waitForPage(driver, "account already exists", false);
        assertTrue(idpConfirmLinkPage.isCurrent());
        assertEquals("User with email user@localhost.com already exists. How do you want to continue?", idpConfirmLinkPage.getMessage());
        idpConfirmLinkPage.clickLinkAccount();
    }


    private void assertUserAuthenticatedInConsumer(String consumerRealmUserId) {
        waitForPage(driver, "keycloak account management", true);
        accountUpdateProfilePage.assertCurrent();
        assertNumFederatedIdentities(consumerRealmUserId, 1);
    }


    // Configure the variant of firstBrokerLogin flow, which will use PasswordForm instead of IdpUsernamePasswordForm.
    // In other words, the form with password-only instead of username/password.
    private static RunOnServer configureBrokerFlowToReAuthenticationWithPasswordForm(String idpAlias, String newFlowAlias) {
        return (session -> {
            // Copy existing firstBrokerLogin flow
            RealmModel appRealm = session.getContext().getRealm();
            AuthenticationFlowModel existingFBLFlow = appRealm.getFlowByAlias(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW);

            AuthenticationFlowModel newFBLFlow = AuthenticationManagementResource.copyFlow(appRealm, existingFBLFlow, newFlowAlias);

            //
            AuthenticationFlowModel reauthenticateSubflow = appRealm.getFlowByAlias(newFlowAlias + " Verify Existing Account by Re-authentication");
            List<AuthenticationExecutionModel> executions = appRealm.getAuthenticationExecutions(reauthenticateSubflow.getId());

            // Remove first execution (IdpUsernamePasswordForm)
            appRealm.removeAuthenticatorExecution(executions.get(0));

            // Increase priority of the second execution (Conditional OTP Subflow)
            executions.get(1).setPriority(30);
            appRealm.updateAuthenticatorExecution(executions.get(1));

            // Add AutoLink Authenticator as first (It will automatically setup user to authentication context)
            AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
            execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution.setAuthenticatorFlow(false);
            execution.setAuthenticator(IdpAutoLinkAuthenticatorFactory.PROVIDER_ID);
            execution.setPriority(10);
            execution.setParentFlow(reauthenticateSubflow.getId());
            execution = appRealm.addAuthenticatorExecution(execution);

            // Add PasswordForm execution
            execution = new AuthenticationExecutionModel();
            execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution.setAuthenticatorFlow(false);
            execution.setAuthenticator(PasswordFormFactory.PROVIDER_ID);
            execution.setPriority(20);
            execution.setParentFlow(reauthenticateSubflow.getId());
            execution = appRealm.addAuthenticatorExecution(execution);

            // Setup new FirstBrokerLogin to identity provider
            IdentityProviderModel idp = appRealm.getIdentityProviderByAlias(idpAlias);
            idp.setFirstBrokerLoginFlowId(newFBLFlow.getId());
            appRealm.updateIdentityProvider(idp);
        });
    }


    // Configure the variant of firstBrokerLogin flow, which will allow to reauthenticate user with password OR totp
    // TOTP will be available just if configured for the user
    private static RunOnServer configureBrokerFlowToReAuthenticationWithPasswordOrTotp(String idpAlias, String newFlowAlias) {
        return (session -> {
            // Copy existing firstBrokerLogin flow
            RealmModel appRealm = session.getContext().getRealm();
            AuthenticationFlowModel existingFBLFlow = appRealm.getFlowByAlias(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW);

            AuthenticationFlowModel newFBLFlow = AuthenticationManagementResource.copyFlow(appRealm, existingFBLFlow, newFlowAlias);

            //
            AuthenticationFlowModel reauthenticateSubflow = appRealm.getFlowByAlias(newFlowAlias + " Verify Existing Account by Re-authentication");
            List<AuthenticationExecutionModel> executions = appRealm.getAuthenticationExecutions(reauthenticateSubflow.getId());

            // Remove both executions (IdpUsernamePasswordForm and Conditional OTP subflow)
            appRealm.removeAuthenticatorExecution(executions.get(0));
            appRealm.removeAuthenticatorExecution(executions.get(1));

            // Add AutoLink Authenticator as first (It will automatically setup user to authentication context)
            AuthenticationExecutionModel execution1 = new AuthenticationExecutionModel();
            execution1.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution1.setAuthenticatorFlow(false);
            execution1.setAuthenticator(IdpAutoLinkAuthenticatorFactory.PROVIDER_ID);
            execution1.setPriority(10);
            execution1.setParentFlow(reauthenticateSubflow.getId());
            execution1 = appRealm.addAuthenticatorExecution(execution1);

            // Add "Password-or-OTP" subflow
            AuthenticationFlowModel passwordOrOtpFlow = new AuthenticationFlowModel();
            passwordOrOtpFlow.setTopLevel(false);
            passwordOrOtpFlow.setBuiltIn(true);
            passwordOrOtpFlow.setAlias("password or otp");
            passwordOrOtpFlow.setDescription("Flow to authenticate user with password or otp");
            passwordOrOtpFlow.setProviderId("basic-flow");
            passwordOrOtpFlow = appRealm.addAuthenticationFlow(passwordOrOtpFlow);
            AuthenticationExecutionModel execution2 = new AuthenticationExecutionModel();
            execution2.setParentFlow(reauthenticateSubflow.getId());
            execution2.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
            execution2.setFlowId(passwordOrOtpFlow.getId());
            execution2.setPriority(20);
            execution2.setAuthenticatorFlow(true);
            appRealm.addAuthenticatorExecution(execution2);

            // Add PasswordForm ALTERNATIVE execution
            AuthenticationExecutionModel execution21 = new AuthenticationExecutionModel();
            execution21.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
            execution21.setAuthenticatorFlow(false);
            execution21.setAuthenticator(PasswordFormFactory.PROVIDER_ID);
            execution21.setPriority(10);
            execution21.setParentFlow(passwordOrOtpFlow.getId());
            execution21 = appRealm.addAuthenticatorExecution(execution21);

            // Add OTPForm ALTERNATIVE execution
            AuthenticationExecutionModel execution22 = new AuthenticationExecutionModel();
            execution22.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE);
            execution22.setAuthenticatorFlow(false);
            execution22.setAuthenticator(OTPFormAuthenticatorFactory.PROVIDER_ID);
            execution22.setPriority(20);
            execution22.setParentFlow(passwordOrOtpFlow.getId());
            execution22 = appRealm.addAuthenticatorExecution(execution22);

            // Setup new FirstBrokerLogin to identity provider
            IdentityProviderModel idp = appRealm.getIdentityProviderByAlias(idpAlias);
            idp.setFirstBrokerLoginFlowId(newFBLFlow.getId());
            appRealm.updateIdentityProvider(idp);
        });
    }

}
