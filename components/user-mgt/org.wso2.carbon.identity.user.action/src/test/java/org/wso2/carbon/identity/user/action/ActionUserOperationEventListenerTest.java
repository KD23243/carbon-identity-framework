package org.wso2.carbon.identity.user.action;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.action.execution.model.ErrorStatus;
import org.wso2.carbon.identity.action.execution.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.Success;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.action.core.factory.UserActionExecutorFactory;
import org.wso2.carbon.identity.user.action.core.listener.ActionUserOperationEventListener;
import org.wso2.carbon.identity.user.action.service.UserActionExecutor;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for ActionUserOperationEventListener.
 */
@WithCarbonHome
public class ActionUserOperationEventListenerTest {

    private static final int DEFAULT_LISTENER_ORDER = 10000;
    public static final String USER_NAME = "USER_NAME";
    public static final String PASSWORD = "PASSWORD";

    private UserStoreManager userStoreManager;
    private UserActionExecutor mockExecutor;
    private MockedStatic<UserCoreUtil> userCoreUtil;

    private ActionUserOperationEventListener listener;

    @BeforeMethod
    public void setUp() {

        userStoreManager = mock(UserStoreManager.class);
        mockExecutor = mock(UserActionExecutor.class);
        userCoreUtil = mockStatic(UserCoreUtil.class);
        listener = new ActionUserOperationEventListener();
        userCoreUtil.when(() -> UserCoreUtil.getDomainName(any())).thenReturn("PRIMARY");
    }

    @AfterMethod
    public void tearDown() {

        userCoreUtil.close();
        UserActionExecutorFactory.unregisterUserActionExecutor(mockExecutor);
    }

    @Test
    public void testGetExecutionOrderId() {

        IdentityEventListenerConfig mockConfig = mock(IdentityEventListenerConfig.class);
        try (MockedStatic<IdentityUtil> identityUtilMockedStatic = mockStatic(IdentityUtil.class)) {
            identityUtilMockedStatic.when(() -> IdentityUtil.readEventListenerProperty(any(), any()))
                    .thenReturn(mockConfig);
            doReturn(5000).when(mockConfig).getOrder();
            Assert.assertEquals(listener.getExecutionOrderId(), 5000);

            doReturn(IdentityCoreConstants.EVENT_LISTENER_ORDER_ID).when(mockConfig).getOrder();
            Assert.assertEquals(listener.getExecutionOrderId(), DEFAULT_LISTENER_ORDER);
        }
    }

    @Test
    public void testDoPreUpdateCredentialByAdminWithID_WithDisabledListener()
            throws UserStoreException {

        IdentityEventListenerConfig mockConfig = mock(IdentityEventListenerConfig.class);
        try (MockedStatic<IdentityUtil> identityUtilMockedStatic = mockStatic(IdentityUtil.class)) {
            identityUtilMockedStatic.when(() -> IdentityUtil.readEventListenerProperty(any(), any()))
                    .thenReturn(mockConfig);
            doReturn("false").when(mockConfig).getEnable();
            Assert.assertTrue(listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD),
                    userStoreManager));
        }
    }

    @Test
    public void testDoPreUpdateCredentialByAdminWithID_Success() throws UserStoreException, ActionExecutionException {

        ActionExecutionStatus<Success> successStatus =
                new SuccessStatus.Builder().setResponseContext(Collections.emptyMap()).build();
        doReturn(successStatus).when(mockExecutor).execute(any(), any());
        doReturn(ActionType.PRE_UPDATE_PASSWORD).when(mockExecutor).getSupportedActionType();
        UserActionExecutorFactory.registerUserActionExecutor(mockExecutor);

        // Call the method
        boolean result = listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD),
                userStoreManager);
        Assert.assertTrue(result, "The method should return true for successful execution.");
    }

    @Test(expectedExceptions = UserStoreClientException.class,
            expectedExceptionsMessageRegExp = "FailureReason. FailureDescription")
    public void testDoPreUpdateCredentialByAdminWithID_Failed() throws UserStoreException, ActionExecutionException {

        Failure failureResponse = new Failure("FailureReason", "FailureDescription");
        ActionExecutionStatus<Failure> failedStatus = new FailedStatus(failureResponse);
        doReturn(failedStatus).when(mockExecutor).execute(any(), any());
        doReturn(ActionType.PRE_UPDATE_PASSWORD).when(mockExecutor).getSupportedActionType();
        UserActionExecutorFactory.registerUserActionExecutor(mockExecutor);

        listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD), userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class,
            expectedExceptionsMessageRegExp = "ErrorMessage. ErrorDescription")
    public void testDoPreUpdateCredentialByAdminWithID_Error() throws UserStoreException, ActionExecutionException {

        Error errorResponse = new Error("ErrorMessage", "ErrorDescription");
        ActionExecutionStatus<Error> errorStatus = new ErrorStatus(errorResponse);
        doReturn(errorStatus).when(mockExecutor).execute(any(), any());
        doReturn(ActionType.PRE_UPDATE_PASSWORD).when(mockExecutor).getSupportedActionType();
        UserActionExecutorFactory.registerUserActionExecutor(mockExecutor);

        // Call the method
        listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD), userStoreManager);
    }


    @Test(expectedExceptions = UserStoreException.class,
            expectedExceptionsMessageRegExp = "Unknown status received from the action executor.")
    public void testDoPreUpdateCredentialByAdminWithID_UnknownStatus()
            throws UserStoreException, ActionExecutionException {

        ActionExecutionStatus<?> unknownStatus = mock(ActionExecutionStatus.class);
        doReturn(null).when(unknownStatus).getStatus();
        doReturn(unknownStatus).when(mockExecutor).execute(any(), any());
        doReturn(ActionType.PRE_UPDATE_PASSWORD).when(mockExecutor).getSupportedActionType();
        UserActionExecutorFactory.registerUserActionExecutor(mockExecutor);

        listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD), userStoreManager);
    }

    @Test(expectedExceptions = UserStoreException.class,
            expectedExceptionsMessageRegExp = "Error while executing pre update password action.")
    public void testDoPreUpdateCredentialByAdminWithID_ActionExecutionException()
            throws UserStoreException, ActionExecutionException {

        doThrow(new ActionExecutionException("Execution error")).when(mockExecutor).execute(any(), any());
        doReturn(ActionType.PRE_UPDATE_PASSWORD).when(mockExecutor).getSupportedActionType();
        UserActionExecutorFactory.registerUserActionExecutor(mockExecutor);

        listener.doPreUpdateCredentialByAdminWithID(USER_NAME, new StringBuffer(PASSWORD), userStoreManager);
    }
}
