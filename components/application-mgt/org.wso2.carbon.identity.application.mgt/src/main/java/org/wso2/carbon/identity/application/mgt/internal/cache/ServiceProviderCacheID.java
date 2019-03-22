/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.mgt.internal.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * Cache to maintain the application id - service provider name.
 */
public class ServiceProviderCacheID extends
        BaseCache<ServiceProviderIDCacheKey, ServiceProviderIDCacheEntry> {

    public static final String SP_CACHE_NAME = "ServiceProviderCache.ID";

    private static volatile ServiceProviderCacheID instance;

    private ServiceProviderCacheID() {

        super(SP_CACHE_NAME);
    }

    public static ServiceProviderCacheID getInstance() {

        if (instance == null) {
            synchronized (ServiceProviderCacheID.class) {
                if (instance == null) {
                    instance = new ServiceProviderCacheID();
                }
            }
        }
        return instance;
    }
}
