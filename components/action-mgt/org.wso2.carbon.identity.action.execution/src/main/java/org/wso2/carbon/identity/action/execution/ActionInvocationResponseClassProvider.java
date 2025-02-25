/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.action.execution;

import org.wso2.carbon.identity.action.execution.impl.DefaultResponseData;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.ResponseData;

/**
 * This interface is used to provide the classes for the action invocation responses defined by the downStream
 * component.
 */
public interface ActionInvocationResponseClassProvider {

    /**
     * Get the supported action type for the public interface ActionInvocationResponseClassProvider.
     *
     * @return Supported action type.
     */
    ActionType getSupportedActionType();

    /**
     * Get the extended ResponseData class for action invocation success response defined by the downstream component.
     *
     * @return The extended ResponseData class.
     */
    default Class<? extends ResponseData> getSuccessResponseDataClass() {

        return DefaultResponseData.class;
    }
}
