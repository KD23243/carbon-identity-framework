/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStateInfo;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.LogoutRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.internal.util.SessionEventPublishingUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.LogConstants.SESSION_CONTEXT_KEY;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.FED_AUTH_NAME;

/**
 * Default implementation of logout request handler.
 */
public class DefaultLogoutRequestHandler implements LogoutRequestHandler {

    private static final Log log = LogFactory.getLog(DefaultLogoutRequestHandler.class);
    private static volatile DefaultLogoutRequestHandler instance;
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private static final String LOGOUT_RETURN_URL_SP_PROPERTY = "logoutReturnUrl";
    private static final String ENABLE_VALIDATING_LOGOUT_RETURN_URL_CONFIG = "CommonAuthCallerPath.EnableValidation";
    private static final String ENABLE_FALLBACK_TO_DEFAULT_LOGOUT_URL_CONFIG =
            "CommonAuthCallerPath.EnableFallbackToDefaultOnNoReturnUrl";
    private static final String DEFAULT_LOGOUT_URL_CONFIG = "CommonAuthCallerPath.DefaultUrl";
    private static final String CONFIGURED_RETURN_URL = ".*";

    public static DefaultLogoutRequestHandler getInstance() {

        if (log.isTraceEnabled()) {
            log.trace("Inside getInstance()");
        }

        if (instance == null) {
            synchronized (DefaultLogoutRequestHandler.class) {

                if (instance == null) {
                    instance = new DefaultLogoutRequestHandler();
                }
            }
        }

        return instance;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
            throws FrameworkException {

        if (log.isTraceEnabled()) {
            log.trace("Inside handle()");
        }
        // This will be initialized only if diagnostic logs are enabled.
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    FrameworkConstants.LogConstants.AUTHENTICATION_FRAMEWORK,
                    FrameworkConstants.LogConstants.ActionIDs.PROCESS_LOGOUT_REQUEST)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        SequenceConfig sequenceConfig = context.getSequenceConfig();
        // Retrieve session information from cache.
        SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(context.getSessionIdentifier(),
                context.getLoginTenantDomain());
        ExternalIdPConfig externalIdPConfig = null;

        // Remove the session related information from the session tables.
        if (SessionDataStore.getInstance().isSessionDataCleanupEnabled()) {
            clearUserSessionData(request);
        }

        // Remove federated authentication session details from the database.
        if (sessionContext != null && StringUtils.isNotBlank(context.getSessionIdentifier()) &&
                sessionContext.getSessionAuthHistory() != null &&
                        sessionContext.getSessionAuthHistory().getHistory() != null) {
            if (FrameworkUtils.isIdpIdColumnAvailableInFedAuthTable()) {
                String fedIdpName = StringUtils.EMPTY;
                if (context.getSubject() != null) {
                    fedIdpName = context.getSubject().getFederatedIdPName();
                }
                if (StringUtils.isNotBlank(fedIdpName)) {
                    for (AuthHistory authHistory : sessionContext.getSessionAuthHistory().getHistory()) {
                        if (FED_AUTH_NAME.equals(authHistory.getAuthenticatorName()) && fedIdpName.equals(authHistory
                                .getIdpName())) {
                            try {
                                int fedIdpId = Integer.parseInt(IdentityProviderManager.getInstance()
                                        .getIdPByName(fedIdpName, context.getTenantDomain()).getId());
                                UserSessionStore.getInstance().removeFederatedAuthSessionInfo(
                                        context.getSessionIdentifier(), fedIdpId);
                                break;
                            } catch (UserSessionException | IdentityProviderManagementException
                                     | NumberFormatException e) {
                                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                                    diagnosticLogBuilder.resultMessage("Error while deleting federated " +
                                                    "authentication session details.")
                                            .inputParam(SESSION_CONTEXT_KEY, context.getSessionIdentifier())
                                            .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                                            .inputParam(LogConstants.InputKeys.IDP, fedIdpName)
                                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                                }
                                throw new FrameworkException("Error while deleting federated authentication session " +
                                        "details for the session context key : " + context.getSessionIdentifier(), e);
                            }
                        }
                    }
                }
            } else {
                for (AuthHistory authHistory : sessionContext.getSessionAuthHistory().getHistory()) {
                    if (FED_AUTH_NAME.equals(authHistory.getAuthenticatorName())) {
                        try {
                            UserSessionStore.getInstance()
                                    .removeFederatedAuthSessionInfo(context.getSessionIdentifier());
                            break;
                        } catch (UserSessionException e) {
                            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                                diagnosticLogBuilder.resultMessage("Error while deleting federated authentication " +
                                                "session details. ")
                                        .inputParam(SESSION_CONTEXT_KEY, context.getSessionIdentifier())
                                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                            }
                            throw new FrameworkException("Error while deleting federated authentication session" +
                                    " details for the session context key : " + context.getSessionIdentifier(), e);
                        }
                    }
                }
            }
        } else if (context.getProperty(FrameworkConstants.FED_IDP_ID) != null) {

            /*
             * There exists a fed idp id which is set by outbound auth saml logout processor.
             * Not explicitly checking for existence of IDP_ID column in FED_AUTH_SESSION_MAPPING table here because
             * FED_IDP_ID will only be set if IDP_ID column exists.
             */

            try {
                UserSessionStore.getInstance().removeFederatedAuthSessionInfo(context.getSessionIdentifier(),
                        Integer.parseInt(context.getProperty(FrameworkConstants.FED_IDP_ID).toString()));
            } catch (UserSessionException | NumberFormatException e) {
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Error while deleting federated authentication " +
                                    "session details.")
                            .inputParam(SESSION_CONTEXT_KEY, context.getSessionIdentifier())
                            .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new FrameworkException("Error while deleting federated authentication session" +
                        " details for the session context key : " + context.getSessionIdentifier(), e);
            }
        }

        // remove SessionContext from the cache and auth cookie before sending logout request to federated IDP,
        // without waiting till a logout response is received from federated IDP.
        // remove the SessionContext from the cache
        FrameworkUtils.removeSessionContextFromCache(context.getSessionIdentifier(), context.getLoginTenantDomain());
        // remove the cookie
        if (IdentityTenantUtil.isTenantedSessionsEnabled()) {
            FrameworkUtils.removeAuthCookie(request, response, context.getLoginTenantDomain());
        } else {
            FrameworkUtils.removeAuthCookie(request, response);
        }
        if (context.isPreviousSessionFound()) {
            // if this is the start of the logout sequence
            if (context.getCurrentStep() == 0) {
                context.setCurrentStep(1);
            }

            int stepCount = sequenceConfig.getStepMap().size();

            while (context.getCurrentStep() <= stepCount) {
                int currentStep = context.getCurrentStep();
                StepConfig stepConfig = sequenceConfig.getStepMap().get(currentStep);
                AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
                if (authenticatorConfig == null) {
                    authenticatorConfig = sequenceConfig.getAuthenticatedReqPathAuthenticator();
                }
                /*
                 * In certain login scenarios which uses `prompt` adaptive function may create steps without
                 * an authenticated authenticator. During the logout flow, we will check those steps and skip
                 * processing those steps further.
                 */
                if (authenticatorConfig == null) {
                    currentStep++;
                    context.setCurrentStep(currentStep);
                    continue;
                }
                ApplicationAuthenticator authenticator =
                        authenticatorConfig.getApplicationAuthenticator();

                String idpName = stepConfig.getAuthenticatedIdP();
                //TODO: Need to fix occurrences where idPName becomes "null"
                if ((idpName == null || "null".equalsIgnoreCase(idpName) || idpName.isEmpty()) &&
                        sequenceConfig.getAuthenticatedReqPathAuthenticator() != null) {
                    idpName = FrameworkConstants.LOCAL_IDP_NAME;
                }
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(idpName, context.getTenantDomain());
                    context.setExternalIdP(externalIdPConfig);
                    context.setAuthenticatorProperties(FrameworkUtils
                            .getAuthenticatorPropertyMapFromIdP(
                                    externalIdPConfig, authenticator.getName()));

                    if (authenticatorConfig.getAuthenticatorStateInfo() != null) {
                        context.setStateInfo(authenticatorConfig.getAuthenticatorStateInfo());
                    } else {
                        context.setStateInfo(
                                getStateInfoFromPreviousAuthenticatedIdPs(idpName, authenticatorConfig.getName(),
                                        context));
                    }

                    AuthenticatorFlowStatus status = authenticator.process(request, response, context);
                    request.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, status);

                    if (!status.equals(AuthenticatorFlowStatus.INCOMPLETE)) {
                        // TODO what if logout fails. this is an edge case
                        currentStep++;
                        context.setCurrentStep(currentStep);
                        continue;
                    }
                    // sends the logout request to the external IdP
                    return;
                } catch (AuthenticationFailedException | LogoutFailedException e) {
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("Exception while handling logout request.")
                                .inputParam(LogConstants.InputKeys.IDP, idpName)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED);

                        // Sanitize the error message before adding to diagnostic log.
                        String errorMessage = e.getMessage();
                        if (context.getLastAuthenticatedUser() != null) {
                            String userName = context.getLastAuthenticatedUser().getUserName();
                            errorMessage = LoggerUtils.getSanitizedErrorMessage(errorMessage, userName);
                        }
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, errorMessage);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    throw new FrameworkException("Exception while handling logout request", e);
                } catch (IdentityProviderManagementException e) {
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("Exception while getting IdP by name")
                                .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    log.error("Exception while getting IdP by name", e);
                }
            }
        } else if (context.getPreviousAuthenticatedIdPs().size() != 0) {
            for (AuthenticatedIdPData authenticatedIdPData: context.getPreviousAuthenticatedIdPs().values()) {
                List<AuthenticatorConfig> authenticatorConfigs = authenticatedIdPData.getAuthenticators();
                for (AuthenticatorConfig authenticatorConfig: authenticatorConfigs) {
                    String authenticatedIdPName = authenticatedIdPData.getIdpName();
                    ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();
                    String authenticatorName = authenticator.getName();

                    // Check whether the IDP and related authenticator is already logged out.
                    if (context.isLoggedOutAuthenticator(authenticatedIdPName, authenticatorName)) {
                        continue;
                    }

                    try {
                        externalIdPConfig = ConfigurationFacade.getInstance()
                                .getIdPConfigByName(authenticatedIdPName, context.getTenantDomain());
                        context.setExternalIdP(externalIdPConfig);
                        context.setAuthenticatorProperties(FrameworkUtils.getAuthenticatorPropertyMapFromIdP(
                                externalIdPConfig, authenticatorName)
                        );
                        if (authenticatorConfig.getAuthenticatorStateInfo() != null) {
                            context.setStateInfo(authenticatorConfig.getAuthenticatorStateInfo());
                        } else {
                            context.setStateInfo(getStateInfoFromPreviousAuthenticatedIdPs(
                                    authenticatedIdPName, authenticatorConfig.getName(), context));
                        }

                        AuthenticatorFlowStatus status = authenticator.process(request, response, context);
                        request.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, status);
                        if (status.equals(AuthenticatorFlowStatus.INCOMPLETE)) {
                            return;
                        }
                        context.addLoggedOutAuthenticator(authenticatedIdPName, authenticatorName);
                    } catch (AuthenticationFailedException | LogoutFailedException e) {
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            diagnosticLogBuilder.resultMessage("Exception while handling logout request")
                                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                            // Sanitize the error message before adding to diagnostic log.
                            String errorMessage = e.getMessage();
                            if (context.getLastAuthenticatedUser() != null) {
                                String userName = context.getLastAuthenticatedUser().getUserName();
                                errorMessage = LoggerUtils.getSanitizedErrorMessage(errorMessage, userName);
                            }
                            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, errorMessage);
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        throw new FrameworkException("Exception while handling logout request", e);
                    } catch (IdentityProviderManagementException e) {
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            diagnosticLogBuilder.resultMessage("Exception while getting IdP by name")
                                    .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        log.error("Exception while getting IdP by name", e);
                    }
                }
            }
        }

        if (FrameworkServiceDataHolder.getInstance().getAuthnDataPublisherProxy() != null &&
                FrameworkServiceDataHolder.getInstance().getAuthnDataPublisherProxy().isEnabled(context) &&
                sessionContext != null) {
            Object authenticatedUserObj = sessionContext.getProperty(FrameworkConstants.AUTHENTICATED_USER);
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            if (authenticatedUserObj instanceof AuthenticatedUser) {
                authenticatedUser = (AuthenticatedUser) authenticatedUserObj;
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                    LoggerUtils.getMaskedContent(authenticatedUser.getUserName()) :
                                    authenticatedUser.getUserName())
                            .inputParam(LogConstants.InputKeys.USER_ID, authenticatedUser.getLoggableUserId());
                }
            }
            // Setting the authenticated user's object to the request to get the relevant details to log out the user.
            context.setProperty(FrameworkConstants.AUTHENTICATED_USER, authenticatedUser);
            FrameworkUtils.publishSessionEvent(context.getSessionIdentifier(), request, context,
                    sessionContext, authenticatedUser, FrameworkConstants.AnalyticsAttributes
                            .SESSION_TERMINATE);
            // Publishing the session termination V2 event for improved event handling.
            SessionEventPublishingUtil.publishSessionTerminationEvent(
                    context.getSessionIdentifier(), authenticatedUser, request, context, sessionContext);
        }

        try {
            context.clearLoggedOutAuthenticators();
            sendResponse(request, response, context, true);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Successfully completed the logout flow.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (ServletException | IOException e) {
            throw new FrameworkException(e.getMessage(), e);
        }
    }

    protected void sendResponse(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationContext context, boolean isLoggedOut)
            throws ServletException, IOException {

        if (log.isTraceEnabled()) {
            log.trace("Inside sendLogoutResponseToCaller()");
        }

        // Set values to be returned to the calling servlet as request
        // attributes
        request.setAttribute(FrameworkConstants.ResponseParams.LOGGED_OUT, isLoggedOut);

        if (Boolean.valueOf(IdentityUtil.getProperty(ENABLE_VALIDATING_LOGOUT_RETURN_URL_CONFIG))) {
            if (isLoggedOut && !isValidCallerPath(context)) {
                log.debug("The commonAuthCallerPath param specified in the request does not satisfy the logout" +
                        " return url specified. Therefore directing to the default logout return url.");
                context.setCallerPath(getDefaultLogoutReturnUrl());
            }
        } else {
            log.debug("Skipping validation of the commonAuthCallerPath param as this validation is not enabled.");
        }

        String redirectURL;
        try {
            redirectURL = FrameworkUtils.buildCallerPathRedirectURL(context.getCallerPath(), context);
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while generating redirect URL.", e);
            }
            redirectURL = context.getCallerPath();
        }
        if (context.getCallerSessionKey() != null) {
            request.setAttribute(FrameworkConstants.SESSION_DATA_KEY, context.getCallerSessionKey());

            AuthenticationResult authenticationResult = new AuthenticationResult();
            authenticationResult.setLoggedOut(true);

            SequenceConfig sequenceConfig = context.getSequenceConfig();
            if (sequenceConfig != null) {
                authenticationResult.setSaaSApp(sequenceConfig.getApplicationConfig().isSaaSApp());
            }

            if (FrameworkUtils.getCacheDisabledAuthenticators().contains(context.getRequestType())
                    && (response instanceof CommonAuthResponseWrapper) &&
                    !((CommonAuthResponseWrapper) response).isWrappedByFramework()) {
                //Set authentication result as request attribute
                addAuthenticationResultToRequest(request, authenticationResult);
            } else {
                FrameworkUtils.addAuthenticationResultToCache(context.getCallerSessionKey(), authenticationResult);
            }

            String sessionDataKeyParam = FrameworkConstants.SESSION_DATA_KEY + "=" +
                    URLEncoder.encode(context.getCallerSessionKey(), "UTF-8");
            redirectURL = FrameworkUtils.appendQueryParamsStringToUrl(redirectURL, sessionDataKeyParam);
        }

        /*
         * TODO Cache retaining is a temporary fix. Remove after Google fixes
         * http://code.google.com/p/gdata-issues/issues/detail?id=6628
         */
        String retainCache = System.getProperty("retainCache");

        if (retainCache == null) {
            FrameworkUtils.removeAuthenticationContextFromCache(context.getContextIdentifier());
        }

        if (log.isDebugEnabled()) {
            log.debug("Sending response back to: " + context.getCallerPath() + "...\n"
                      + FrameworkConstants.ResponseParams.LOGGED_OUT + " : " + isLoggedOut + "\n"
                      + FrameworkConstants.SESSION_DATA_KEY + ": " + context.getCallerSessionKey());
        }

        // redirect to the caller
        response.sendRedirect(redirectURL);
    }

    /**
     * Add authentication result into request attribute
     *
     * @param request Http servlet request
     * @param authenticationResult Authentication result
     */
    private void addAuthenticationResultToRequest(HttpServletRequest request,
            AuthenticationResult authenticationResult) {
        request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT, authenticationResult);
    }

    private AuthenticatorStateInfo getStateInfoFromPreviousAuthenticatedIdPs(String idpName, String authenticatorName,
            AuthenticationContext context) {

        if (context.getPreviousAuthenticatedIdPs() == null
                || context.getPreviousAuthenticatedIdPs().get(idpName) == null
                || context.getPreviousAuthenticatedIdPs().get(idpName).getAuthenticators() == null) {
            return null;
        }

        for (AuthenticatorConfig authenticatorConfig : context.getPreviousAuthenticatedIdPs().get(idpName)
                .getAuthenticators()) {
            if (authenticatorName.equals(authenticatorConfig.getName())) {
                return authenticatorConfig.getAuthenticatorStateInfo();
            }
        }
        return null;
    }

    /**
     * Clear the user session information related to the given logout request if the user session management feature
     * is enabled.
     *
     * @param request logout request
     */
    private void clearUserSessionData(HttpServletRequest request) {

        if (!FrameworkServiceDataHolder.getInstance().isUserSessionMappingEnabled()) {
            return;
        }
        Cookie commonAuthCookie = FrameworkUtils.getAuthCookie(request);
        if (commonAuthCookie != null) {
            String commonAuthCookieValue = commonAuthCookie.getValue();
            String sessionId = null;
            if (commonAuthCookieValue != null) {
                sessionId = DigestUtils.sha256Hex(commonAuthCookieValue);
            }
            if (sessionId != null) {
                List<String> terminatedSessionId = new ArrayList<>();
                terminatedSessionId.add(sessionId);
                UserSessionStore.getInstance().removeTerminatedSessionRecords(terminatedSessionId);
            }
        }
    }

    private boolean isValidCallerPath(AuthenticationContext context) {

        // Internal redirection urls will always be relative paths and validation can therefore be skipped.
        try {
            if (FrameworkUtils.isURLRelative(context.getCallerPath())) {
                return true;
            }
        } catch (URISyntaxException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
            return false;
        }

        // This is an external redirection.
        if (StringUtils.isNotBlank(context.getRelyingParty())) {
            try {
                String configuredReturnUrl = getRegisteredLogoutReturnUrl(context.getRelyingParty(), context
                        .getRequestType(), context.getTenantDomain());
                // If the config to fall back to default logout url when the logout return url is not set at the
                // application level is enabled, then the validation should return false when the configured Return Url
                // is set to .*. This will set the logout return url to default logout url after this method execution.
                if (Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_FALLBACK_TO_DEFAULT_LOGOUT_URL_CONFIG))
                        && CONFIGURED_RETURN_URL.equals(configuredReturnUrl)) {
                    log.debug("The configured return url is set to .*. Logout return url validation will be failed " +
                            "to fallback to default logout url.");
                    return false;
                }
                return context.getCallerPath().matches(configuredReturnUrl);
            } catch (IdentityApplicationManagementException e) {
                return false;
            }
        }
        log.debug("The relying party in the authentication context is empty. Therefore, the logout return url" +
                " cannot not be validated.");
        return Boolean.FALSE;
    }

    private String getRegisteredLogoutReturnUrl(String relyingParty, String requestType, String tenantDomain) throws
            IdentityApplicationManagementException {

        if (FrameworkConstants.OIDC.equals(requestType)) {
            requestType = FrameworkConstants.OAUTH2;
        }
        String configuredReturnUrl = CONFIGURED_RETURN_URL;
        ApplicationManagementService appMgtService = ApplicationManagementService.getInstance();
        ServiceProvider serviceProvider = appMgtService.getServiceProviderByClientId(relyingParty, requestType,
                tenantDomain);
        if (serviceProvider != null && serviceProvider.getSpProperties() != null) {
            for (ServiceProviderProperty spProperty : serviceProvider.getSpProperties()) {
                if (LOGOUT_RETURN_URL_SP_PROPERTY.equals(spProperty.getName())) {
                    configuredReturnUrl = spProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Logout caller path validation is configured for service provider of " +
                                relyingParty);
                    }
                    break;
                }
            }
        }
        return configuredReturnUrl;
    }

    private String getDefaultLogoutReturnUrl() {

        String defaultLogoutUrl = IdentityUtil.getProperty(DEFAULT_LOGOUT_URL_CONFIG);
        if (StringUtils.isBlank(defaultLogoutUrl)) {
            if (log.isDebugEnabled()) {
                log.debug("The default logout URL is not set in the identity.xml file. Therefore directing to the " +
                        "default logout page of the server.");
            }
            defaultLogoutUrl = "/authenticationendpoint/samlsso_logout.do";
        }
        return defaultLogoutUrl;
    }
}
