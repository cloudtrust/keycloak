package org.keycloak.testsuite.forms;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.browser.CookieAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.PasswordFormFactory;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalBlockRoleAuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalBlockUserConfiguredAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.ActionURIUtils;
import org.keycloak.testsuite.auth.page.login.OneTimeCode;
import org.keycloak.testsuite.broker.SocialLoginTest;
import org.keycloak.testsuite.model.ClientModelTest;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.LoginTotpPage;
import org.keycloak.testsuite.pages.LoginUsernameOnlyPage;
import org.keycloak.testsuite.pages.PasswordPage;
import org.keycloak.testsuite.runonserver.RunOnServer;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.FlowUtil;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.URLUtils;
import org.openqa.selenium.WebDriver;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;
import static org.keycloak.testsuite.arquillian.DeploymentTargetModifier.AUTH_SERVER_CURRENT;
import static org.keycloak.testsuite.broker.SocialLoginTest.Provider.GITHUB;
import static org.keycloak.testsuite.broker.SocialLoginTest.Provider.GITLAB;
import static org.keycloak.testsuite.broker.SocialLoginTest.Provider.GOOGLE;

public class BrowserFlowTest extends AbstractTestRealmKeycloakTest {
    private static final String INVALID_AUTH_CODE = "Invalid authenticator code.";

    @ArquillianResource
    protected OAuthClient oauth;

    @Drone
    protected WebDriver driver;

    @Page
    protected LoginPage loginPage;

    @Page
    protected LoginUsernameOnlyPage loginUsernameOnlyPage;

    @Page
    protected PasswordPage passwordPage;

    @Page
    protected ErrorPage errorPage;

    @Page
    protected LoginTotpPage loginTotpPage;

    @Page
    private OneTimeCode oneTimeCodePage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Deployment
    @TargetsContainer(AUTH_SERVER_CURRENT)
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class, ClientModelTest.class)
                .addPackages(true,
                        "org.keycloak.testsuite",
                        "org.keycloak.testsuite.model");
    }

    private RealmRepresentation loadTestRealm() {
        RealmRepresentation res = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        res.setBrowserFlow("browser");
        return res;
    }

    private void importTestRealm(Consumer<RealmRepresentation> realmUpdater) {
        RealmRepresentation realm = loadTestRealm();
        if (realmUpdater != null) {
            realmUpdater.accept(realm);
        }
        importRealm(realm);
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        log.debug("Adding test realm for import from testrealm.json");
        testRealms.add(loadTestRealm());
    }

    private void provideUsernamePassword(String user) {
        // Go to login page
        loginPage.open();
        loginPage.assertCurrent();

        // Login attempt with an invalid password
        loginPage.login(user, "invalid");
        loginPage.assertCurrent();

        // Login attempt with a valid password - user with configured OTP
        loginPage.login(user, "password");
    }

    private String getOtpCode(String key) {
        return new TimeBasedOTP().generateTOTP(key);
    }

    @Test
    public void testUserWithoutAdditionalFactorConnection() {
        provideUsernamePassword("test-user@localhost");
        Assert.assertFalse(loginPage.isCurrent());
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
        Assert.assertFalse(loginTotpPage.isCurrent());
        loginTotpPage.assertCredentialsComboboxAvailability(false);
    }

    @Test
    public void testUserWithOneAdditionalFactorOtpFails() {
        provideUsernamePassword("user-with-one-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
        loginTotpPage.assertCurrent();
        loginTotpPage.assertCredentialsComboboxAvailability(false);

        oneTimeCodePage.sendCode("123456");
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void testUserWithOneAdditionalFactorOtpSuccess() {
        provideUsernamePassword("user-with-one-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
        loginTotpPage.assertCurrent();
        loginTotpPage.assertCredentialsComboboxAvailability(false);

        oneTimeCodePage.sendCode(getOtpCode("DJmQfC73VGFhw7D4QJ8A"));
        Assert.assertFalse(loginPage.isCurrent());
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void testBackButton() {
        provideUsernamePassword("user-with-one-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());

        // Assert "Back" button available on the TOTP page
        loginTotpPage.assertBackButtonAvailability(true);
        loginTotpPage.clickBackButton();

        // Assert "Back" button not available on the Browser page
        loginPage.assertCurrent();
        loginPage.assertBackButtonAvailability(false);

        // Login
        loginPage.login("user-with-one-configured-otp", "password");

        oneTimeCodePage.sendCode(getOtpCode("DJmQfC73VGFhw7D4QJ8A"));
        Assert.assertFalse(loginPage.isCurrent());
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }

    @Test
    public void testUserWithTwoAdditionalFactors() {
        final String firstKey = "DJmQfC73VGFhw7D4QJ8A";
        final String secondKey = "ABCQfC73VGFhw7D4QJ8A";

        // Provide username and password
        provideUsernamePassword("user-with-two-configured-otp");
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
        loginTotpPage.assertCurrent();
        loginTotpPage.assertCredentialsComboboxAvailability(true);

        // Check that selected credential is "first"
        Assert.assertEquals("first", loginTotpPage.getSelectedCredential());

        // Select "second" factor but try to connect with the OTP code from the "first" one
        oneTimeCodePage.selectFactor("second");
        oneTimeCodePage.sendCode(getOtpCode(firstKey));
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());

        // Select "first" factor but try to connect with the OTP code from the "second" one
        oneTimeCodePage.selectFactor("first");
        oneTimeCodePage.sendCode(getOtpCode(secondKey));
        Assert.assertEquals(INVALID_AUTH_CODE, oneTimeCodePage.getError());

        // Select "second" factor and try to connect with its OTP code
        oneTimeCodePage.selectFactor("second");
        oneTimeCodePage.sendCode(getOtpCode(secondKey));
        Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
    }

    private void testCredentialsOrder(String username, List<String> orderedCredentials) {
        // Provide username and password
        provideUsernamePassword(username);
        Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
        loginTotpPage.assertCurrent();
        loginTotpPage.assertCredentialsComboboxAvailability(true);

        // Check that preferred credential is selected
        Assert.assertEquals(orderedCredentials.get(0), loginTotpPage.getSelectedCredential());
        // Check credentials order
        List<String> creds = loginTotpPage.getAvailableCredentials();
        Assert.assertEquals(2, creds.size());
        Assert.assertEquals(orderedCredentials, creds);
    }

    @Test
    public void testCredentialsOrder() {
        String username = "user-with-two-configured-otp";
        int idxFirst = 0; // Credentials order is: first, password, second

        // Priority tells: first then second
        testCredentialsOrder(username, Arrays.asList("first", "second"));

        try {
            // Move first credential in last position
            importTestRealm(realmRep -> {
                UserRepresentation user = realmRep.getUsers().stream().filter(u -> username.equals(u.getUsername())).findFirst().get();
                // Move first OTP after second while priority are not used for import
                user.getCredentials().add(user.getCredentials().remove(idxFirst));
            });

            // Priority tells: second then first
            testCredentialsOrder(username, Arrays.asList("second", "first"));
        } finally {
            // Restore default testrealm.json
            importTestRealm(null);
        }
    }

    // In a sub-flow with alternative credential executors, check which credentials are available and in which order
    @Test
    public void testAlternativeCredentials() {
        try {
            testingClient.server("test").run(configureBrowserFlowWithAlternativeCredentials());

            // test-user has not other credential than his password. No combobox is displayed 
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("test-user@localhost");
            loginTotpPage.assertCredentialsComboboxAvailability(false);

            // A user with only one other credential than his password: the combobox should
            // let him choose between his password and his OTP credentials
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-one-configured-otp");
            loginTotpPage.assertCredentialsComboboxAvailability(true);
            Assert.assertEquals(Arrays.asList("Password", "OTP"), loginTotpPage.getAvailableCredentials());

            // A user with two other credentials than his password: the combobox should
            // let him choose between his 3 credentials in the order of his preferences
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-two-configured-otp");
            loginTotpPage.assertCredentialsComboboxAvailability(true);
            Assert.assertEquals("OTP - first", loginTotpPage.getSelectedCredential());
            Assert.assertEquals(Arrays.asList("OTP - first", "Password", "OTP - second"), loginTotpPage.getAvailableCredentials());
        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
            importTestRealm(null);
        }
    }

    private RunOnServer configureBrowserFlowWithAlternativeCredentials() {
        final String newFlowAlias = "browser - alternative";
        return session ->
                FlowUtil.inCurrentRealm(session)
                        .copyBrowserFlow(newFlowAlias)
                        .inForms(forms -> forms
                                .clear()
                                .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                                .addSubFlowExecution(Requirement.CONDITIONAL, altSubFlow -> altSubFlow
                                        // Add authenticators to this flow: 1 conditional block and 2 basic authenticator executions
                                        .addAuthenticatorExecution(Requirement.REQUIRED, ConditionalBlockUserConfiguredAuthenticatorFactory.PROVIDER_ID)
                                        .addAuthenticatorExecution(Requirement.ALTERNATIVE, PasswordFormFactory.PROVIDER_ID)
                                        .addAuthenticatorExecution(Requirement.ALTERNATIVE, OTPFormAuthenticatorFactory.PROVIDER_ID)
                                )
                        )
                        .defineAsBrowserFlow();
    }

    // In a form waiting for a username only, provides a username and check if password is requested in the following execution of the flow
    private boolean needsPassword(String username) {
        // provides username
        loginUsernameOnlyPage.open();
        loginUsernameOnlyPage.login(username);

        return passwordPage.isCurrent();
    }

    // A conditional block without conditional block should automatically be disabled
    @Test
    public void testFlowDisabledWhenConditionalBlockIsMissing() {
        try {
            testingClient.server("test").run(configureBrowserFlowWithConditionalSubFlowHavingConditionalBlock("browser - non missing conditional block", true));
            Assert.assertTrue(needsPassword("user-with-two-configured-otp"));

            testingClient.server("test").run(configureBrowserFlowWithConditionalSubFlowHavingConditionalBlock("browser - missing conditional block", false));
            // Flow is conditional but it is missing a conditional authentication executor
            // The whole flow is disabled
            Assert.assertFalse(needsPassword("user-with-two-configured-otp"));
        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }

    private RunOnServer configureBrowserFlowWithConditionalSubFlowHavingConditionalBlock(String newFlowAlias, boolean conditionFlowHasConditionalBlock) {
        return session ->
                FlowUtil.inCurrentRealm(session)
                        .copyBrowserFlow(newFlowAlias)
                        .inForms(forms -> forms
                                .clear()
                                .addAuthenticatorExecution(Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                                .addSubFlowExecution(Requirement.CONDITIONAL, subFlow -> {
                                    if (conditionFlowHasConditionalBlock) {
                                        // Add authenticators to this flow: 1 conditional block and a basic authenticator executions
                                        subFlow.addAuthenticatorExecution(Requirement.REQUIRED, ConditionalBlockUserConfiguredAuthenticatorFactory.PROVIDER_ID);
                                    }
                                    // Update the browser forms only with a UsernameForm
                                    subFlow.addAuthenticatorExecution(Requirement.REQUIRED, PasswordFormFactory.PROVIDER_ID);
                                }))
                        .defineAsBrowserFlow();
    }

    // Configure a conditional block in a non-conditional sub-flow
    // In such case, the whole sub-flow should be disabled
    @Test
    public void testConditionalBlockInNonConditionalFlow() {
        try {
            testingClient.server("test").run(configureBrowserFlowWithConditionalBlockInNonConditionalFlow());

            // provides username
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-two-configured-otp");

            // if flow was conditional, the conditional block would disable the flow because no user have the expected role
            // Here, the password form is shown: it shows that the executor of the conditional bloc has been disabled. Other
            // executors of this flow are executed anyway
            passwordPage.assertCurrent();
        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }

    private RunOnServer configureBrowserFlowWithConditionalBlockInNonConditionalFlow() {
        String newFlowAlias = "browser - nonconditional";
        String requiredRole = "non-existing-role";
        return session ->
                FlowUtil.inCurrentRealm(session)
                        .copyBrowserFlow(newFlowAlias)
                        .inForms(forms -> forms
                                .clear()
                                .addAuthenticatorExecution(Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                                .addSubFlowExecution(Requirement.REQUIRED, subFlow -> subFlow
                                        // Add authenticators to this flow: 1 conditional block and a basic authenticator executions
                                        .addAuthenticatorExecution(Requirement.REQUIRED, ConditionalBlockRoleAuthenticatorFactory.PROVIDER_ID,
                                                config -> config.getConfig().put("condUserRole", requiredRole))
                                        .addAuthenticatorExecution(Requirement.REQUIRED, PasswordFormFactory.PROVIDER_ID)
                                )
                        )
                        .defineAsBrowserFlow();

    }

    // Check the ConditionalBlockRoleAuthenticator
    // Configure a conditional subflow with the required role "user" and an OTP authenticator
    // user-with-two-configured-otp has the "user" role and should be asked for an OTP code
    // user-with-one-configured-otp does not have the role. He should not be asked for an OTP code
    @Test
    public void testConditionalBlockRoleAuthenticator() {
        String requiredRole = "user";
        // A browser flow is configured with an OTPForm for users having the role "user"
        testingClient.server("test").run(configureBrowserFlowOTPNeedsRole(requiredRole));

        try {
            // user-with-two-configured-otp has been configured with role "user". He should be asked for an OTP code
            provideUsernamePassword("user-with-two-configured-otp");
            Assert.assertTrue(oneTimeCodePage.isOtpLabelPresent());
            loginTotpPage.assertCurrent();
            loginTotpPage.assertCredentialsComboboxAvailability(true);

            // user-with-one-configured-otp has not configured role. He should not be asked for an OTP code
            provideUsernamePassword("user-with-one-configured-otp");
            Assert.assertFalse(oneTimeCodePage.isOtpLabelPresent());
            Assert.assertFalse(loginTotpPage.isCurrent());
        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }

    // Configure a flow with a conditional sub flow with a condition where a specific role is required 
    private RunOnServer configureBrowserFlowOTPNeedsRole(String requiredRole) {
        final String newFlowAlias = "browser - rule";
        return session ->
                FlowUtil.inCurrentRealm(session)
                        .copyBrowserFlow(newFlowAlias)
                        .inForms(forms -> forms
                                .clear()
                                // Update the browser forms with a UsernamePasswordForm
                                .addAuthenticatorExecution(Requirement.REQUIRED, UsernamePasswordFormFactory.PROVIDER_ID)
                                .addSubFlowExecution(Requirement.CONDITIONAL, subFlow -> subFlow
                                        .addAuthenticatorExecution(Requirement.REQUIRED, ConditionalBlockRoleAuthenticatorFactory.PROVIDER_ID,
                                                config -> config.getConfig().put("condUserRole", requiredRole))
                                        .addAuthenticatorExecution(Requirement.REQUIRED, OTPFormAuthenticatorFactory.PROVIDER_ID)
                                )
                        )
                        .defineAsBrowserFlow();
    }

    @Test
    public void testAlternativeSubFlowWithAlwaysValidatingExecutor() {
        testingClient.server("test").run(configureBrowserFlowSubFlowWithAlwaysValidatingExecutor());
        try {
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.login("user-with-one-configured-otp");
        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }

    private RunOnServer configureBrowserFlowSubFlowWithAlwaysValidatingExecutor() {
        return session -> FlowUtil.inCurrentRealm(session)
                .copyBrowserFlow("Browser - altflow validatingexecutor")
                .inForms(forms -> forms
                        .clear()
                        .addAuthenticatorExecution(Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                        .addSubFlowExecution(Requirement.REQUIRED, subFlow -> subFlow
                                .addSubFlowExecution(Requirement.ALTERNATIVE, altFlow -> altFlow
                                        .addAuthenticatorExecution(Requirement.REQUIRED, CookieAuthenticatorFactory.PROVIDER_ID)
                                        .addAuthenticatorExecution(Requirement.REQUIRED, "identity-provider-redirector"))
                        )
                )
                .defineAsBrowserFlow();
    }

    @Test
    public void testSwitchExecutionNotAllowedWithRequiredPasswordAndAlternativeOTP() {
        String newFlowAlias = "browser - copy 1";
        testingClient.server("test").run(configureBrowserFlowWithRequiredPasswordFormAndAlternativeOTP(newFlowAlias));

        try {
            loginUsernameOnlyPage.open();
            loginUsernameOnlyPage.assertCurrent();
            loginUsernameOnlyPage.login("user-with-one-configured-otp");

            // Assert on password page now
            passwordPage.assertCurrent();

            String otpAuthenticatorExecutionId = realmsResouce().realm("test").flows().getExecutions(newFlowAlias)
                    .stream()
                    .filter(execution -> OTPFormAuthenticatorFactory.PROVIDER_ID.equals(execution.getProviderId()))
                    .findFirst()
                    .get()
                    .getId();

            // Manually run request to switch execution to OTP. It shouldn't be allowed and error should be thrown
            String actionURL = ActionURIUtils.getActionURIFromPageSource(driver.getPageSource());
            String formParameters = Constants.AUTHENTICATION_EXECUTION + "=" + otpAuthenticatorExecutionId + "&"
                    + Constants.CREDENTIAL_ID + "=";

            URLUtils.sendPOSTRequestWithWebDriver(actionURL, formParameters);

            errorPage.assertCurrent();

        } finally {
            testingClient.server("test").run(setBrowserFlowToRealm());
        }
    }


    @Test
    public void testSocialProvidersPresentOnLoginUsernameOnlyPageIfConfigured() {
        String testRealm = "test";
        // Test setup - Configure the testing Keycloak instance with UsernameForm & PasswordForm (both REQUIRED) and OTPFormAuthenticator (ALTERNATIVE)
        testingClient.server(testRealm).run(configureBrowserFlowWithRequiredPasswordFormAndAlternativeOTP("browser - copy 1"));

        try {
            SocialLoginTest socialLoginTest = new SocialLoginTest();

            // Add some sample dummy GitHub, Gitlab & Google social providers to the testing realm. Dummy because they won't be fully
            // functional (won't have proper Client ID & Client Secret defined). But that doesn't matter for this particular test. What
            // matters is if they are visible (clickable) on the LoginUsernameOnlyPage once the page is loaded
            for (SocialLoginTest.Provider provider : Arrays.asList(GITHUB, GITLAB, GOOGLE)) {
                adminClient.realm(testRealm).identityProviders().create(socialLoginTest.buildIdp(provider));

                loginUsernameOnlyPage.open();
                loginUsernameOnlyPage.assertCurrent();
                // For each of the testing social providers, check the particular social provider button is present on the UsernameForm
                // Test succeeded if NoSuchElementException is thrown for none of them
                loginUsernameOnlyPage.findSocialButton(provider.id());
            }

            // Test cleanup - Return back to the initial state
        } finally {
            // Drop the testing social providers previously created within the test
            for (IdentityProviderRepresentation providerRepresentation : adminClient.realm(testRealm).identityProviders().findAll()) {
                adminClient.realm(testRealm).identityProviders().get(providerRepresentation.getInternalId()).remove();
            }
            // Reset Authentication flow back to the default Browser flow one
            testingClient.server(testRealm).run(setBrowserFlowToRealm());
        }
    }

    // Configure the browser flow with those 3 authenticators at same level as subflows of the "Form":
    // UsernameForm: REQUIRED
    // PasswordForm: REQUIRED
    // OTPFormAuthenticator: ALTERNATIVE
    // In reality, the configuration of the flow like this doesn't have much sense, but nothing prevents administrator to configure it at this moment
    private static RunOnServer configureBrowserFlowWithRequiredPasswordFormAndAlternativeOTP(String newFlowAlias) {
        return session ->
                FlowUtil.inCurrentRealm(session)
                        .copyBrowserFlow(newFlowAlias)
                        .inForms(forms ->
                                forms
                                        .clear()
                                        // Add REQUIRED UsernameForm Authenticator as first
                                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, UsernameFormFactory.PROVIDER_ID)
                                        // Add REQUIRED PasswordForm Authenticator as second
                                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.REQUIRED, PasswordFormFactory.PROVIDER_ID)
                                        // Add OTPForm ALTERNATIVE execution as third
                                        .addAuthenticatorExecution(AuthenticationExecutionModel.Requirement.ALTERNATIVE, OTPFormAuthenticatorFactory.PROVIDER_ID)
                        )
                        // Activate this new flow
                        .defineAsBrowserFlow();
    }

    private static RunOnServer setBrowserFlowToRealm() {
        return session -> {
            RealmModel appRealm = session.getContext().getRealm();
            AuthenticationFlowModel existingBrowserFlow = appRealm.getFlowByAlias(DefaultAuthenticationFlows.BROWSER_FLOW);
            appRealm.setBrowserFlow(existingBrowserFlow);
        };
    }
}
