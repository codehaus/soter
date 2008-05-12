/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.soter.rbac.jacc;

import java.util.HashMap;
import java.util.Map;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;

/**
 * @version $Rev:$ $Date:$
 */
public class RbacPolicyConfigurationFactory extends PolicyConfigurationFactory {
    private static RbacPolicyConfigurationFactory singleton;
    private RbacBean rbacBean;
    private final Map<String, RbacPolicyConfiguration> policyConfigurationMap = new HashMap<String, RbacPolicyConfiguration>();

    public RbacPolicyConfigurationFactory() {
        synchronized (RbacPolicyConfigurationFactory.class) {
            if (singleton != null) {
                throw new IllegalStateException("There is already an RbacPolicyConfigurationFactory created");
            }
            singleton = this;
        }
    }

    public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
        RbacPolicyConfiguration policyConfiguration = policyConfigurationMap.get(contextID);
        if (policyConfiguration == null) {
            policyConfiguration = rbacBean.newPolicyConfiguration(contextID);
            policyConfigurationMap.put(contextID, policyConfiguration);
        } else {
            policyConfiguration.open(remove);
        }
        return policyConfiguration;
    }
    
    public RbacPolicyConfiguration getPolicyConfiguration(String contextID) {
        return policyConfigurationMap.get(contextID);
    }

    public boolean inService(String contextID) throws PolicyContextException {
        return getPolicyConfiguration(contextID, false).inService();
    }

    public static RbacPolicyConfigurationFactory getSingleton() {
        return singleton;
    }

    public void setRbacBean(RbacBean rbacBean) {
        this.rbacBean = rbacBean;
    }
}
