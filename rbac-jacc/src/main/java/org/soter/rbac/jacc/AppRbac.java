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

import java.util.Set;
import java.util.HashSet;
import java.util.List;

import javax.security.jacc.PolicyContextException;

import org.soter.rbac.model.RbacType;
import org.soter.rbac.model.ScopeType;

/**
 * Contains a sub-rbac model for a specific app, to be merged into a full rbac model
 * @version $Rev:$ $Date:$
 */
public class AppRbac {

    private final String appId;
    private final RbacType rbac;
    private final RbacBean environment;
    private final ClassLoader cl;
    private final int moduleCount;

    private final Set<ScopeType> commitedScopes = new HashSet<ScopeType>();

    public AppRbac(String appId, RbacType rbac, RbacBean environment, ClassLoader cl, int moduleCount) throws PolicyContextException {
        this.appId = appId;
        this.rbac = rbac;
        this.environment = environment;
        this.cl = cl;
        if (moduleCount > 0) {
            this.moduleCount = moduleCount;
        } else {
            this.moduleCount = getAppScope().getScope().size();
        }
        environment.registerApp(this);
    }

    void commit(ScopeType context) {
        commitedScopes.add(context);
        if (commitedScopes.size() == moduleCount) {
            rbac.start(cl, null);
            environment.merge(rbac);
        }
    }

    void open(ScopeType context) {
        commitedScopes.remove(context);
    }

    public ScopeType getAppScope() throws PolicyContextException {
        List<ScopeType> scopes = rbac.getScope();
        ScopeType appScope = getScope(appId, scopes);
        if (appScope == null) {
            throw new PolicyContextException("No app scope: " + appId);
        }
        return appScope;
    }

    RbacPolicyConfiguration newPolicyConfiguration(String contextID) throws PolicyContextException {
        List<ScopeType> scopes = rbac.getScope();
        ScopeType appScope = getScope(appId, scopes);
        if (appScope == null) {
            throw new PolicyContextException("No app scope: " + appId);
        }
        ScopeType contextScope = getScope(contextID, scopes);
        if (contextScope == null) {
            contextScope = new ScopeType();
            contextScope.setScopeName(contextID);
            scopes.add(contextScope);
        }
        return new RbacPolicyConfiguration(appScope, contextScope, this);
    }

    private ScopeType getScope(String appId, List<ScopeType> scopes) {
        for (ScopeType scope: scopes) {
            if (appId.equals(scope.getScopeName())) {
                return scope;
            }
        }
        return null;
    }

}
