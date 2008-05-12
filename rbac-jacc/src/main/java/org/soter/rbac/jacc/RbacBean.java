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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.soter.rbac.model.RbacType;
import org.soter.rbac.model.RbacXmlUtil;
import org.soter.rbac.model.RoleType;
import org.soter.rbac.model.ScopeType;
import org.xml.sax.SAXException;

/**
 * Configured bean that sets up the rbac policy
 * @version $Rev:$ $Date:$
 */
public class RbacBean {

    private Class principalClass;
    private ClassLoader cl;
    private Map<String, AppRbac> contextToAppMap = new HashMap<String, AppRbac>();
    private AtomicReference<RbacType> rbac = new AtomicReference<RbacType>();
    private RbacPolicyConfigurationFactory factory;
    private final ThreadLocal<AppRbac> threadAppRbac = new ThreadLocal<AppRbac>();

    public RbacBean(Class principalClass, RbacType rbacData, ClassLoader cl) throws JAXBException, IOException, ParserConfigurationException, SAXException, XMLStreamException, PolicyContextException, ClassNotFoundException {
        this.principalClass = principalClass;
        this.cl = cl;
        rbac.set(rbacData);
        rbac.get().start(cl, null);
        RbacPolicy.setRbacBean(this);
        factory = RbacPolicyConfigurationFactory.getSingleton();
        factory.setRbacBean(this);
    }

    public RbacBean(Class principalClass, File rbacData, ClassLoader cl) throws JAXBException, IOException, ParserConfigurationException, SAXException, XMLStreamException, PolicyContextException, ClassNotFoundException {
        this(principalClass, read(rbacData), cl);
    }

    private static RbacType read(File rbacData) throws ParserConfigurationException, IOException, SAXException, JAXBException, XMLStreamException {
        Reader reader = new FileReader(rbacData);
        RbacType rbacType = RbacXmlUtil.loadRbac(reader);
        return rbacType;
    }

    public void setThreadApp(AppRbac appRbac) throws PolicyContextException {
        threadAppRbac.set(appRbac);
        registerApp(appRbac);
    }

    public void registerApp(AppRbac appRbac) throws PolicyContextException {
        ScopeType appScope = appRbac.getAppScope();
        List<ScopeType> contexts = appScope.getScope();
        for (ScopeType context: contexts) {
            contextToAppMap.put(context.getScopeName(), appRbac);
        }
    }

    public void removedApp(AppRbac appRbac) {
        //unmerge
        for (Iterator<Map.Entry<String, AppRbac>> it = contextToAppMap.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, AppRbac> entry = it.next();
            if (entry.getValue().equals(appRbac)) {
                it.remove();
            }
        }
    }

    public void merge(RbacType toMerge) {
        RbacType original = rbac.get();
        RbacType copy;
        do {
            copy = new RbacType(original);
            copy.merge(toMerge);
        } while (!rbac.compareAndSet(original, copy));
    }


    public boolean implies(ProtectionDomain domain, Permission permission) {
        String contextID = PolicyContext.getContextID();
        if (contextID != null) {
            Principal[] principals = domain.getPrincipals();
            for (Principal principal: principals) {
                if (principal.getClass() == principalClass) {
                    String userId = principal.getName();
                    RbacPolicyConfiguration policyConfiguration = factory.getPolicyConfiguration(contextID);
                    if (policyConfiguration.inService()) {
                        List<RoleType> roles = rbac.get().getUserRoles(userId);
                        for (RoleType role : roles) {
                            if (role.implies(permission, contextID)) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
            }
        }
        return false;
    }

    RbacPolicyConfiguration newPolicyConfiguration(String contextID) throws PolicyContextException {
        AppRbac appRbac = contextToAppMap.get(contextID);
        if (appRbac == null) {
            appRbac = threadAppRbac.get();
            contextToAppMap.put(contextID, appRbac);
        }
        if (appRbac == null) {
            throw new PolicyContextException("Cannot determine application for contextID: " + contextID);
        }
        return appRbac.newPolicyConfiguration(contextID);
    }

}
