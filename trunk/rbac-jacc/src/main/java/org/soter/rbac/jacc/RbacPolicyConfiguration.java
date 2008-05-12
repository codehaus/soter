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

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Enumeration;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;

import org.soter.rbac.model.PermissionType;
import org.soter.rbac.model.RoleType;
import org.soter.rbac.model.ScopeType;

/**
 * @version $Rev:$ $Date:$
 */
public class RbacPolicyConfiguration implements PolicyConfiguration {
    private static enum State {
        IN_SERVICE(true),
        DELETED(false),
        OPEN(false);

        private final boolean inService;

        private State(boolean inService) {
            this.inService = inService;
        }

        public boolean isInService() {
            return inService;
        }
    }
    private final ScopeType roleScope;
    private final ScopeType permissionScope;
    private final AppRbac rbac;
    private State state = State.OPEN;
    private static final String UNCHECKED_ROLE = "_UNCHECKED_ROLE_";

    public RbacPolicyConfiguration(ScopeType roleScope, ScopeType permissionScope, AppRbac rbac) {
        this.roleScope = roleScope;
        this.permissionScope = permissionScope;
        this.rbac = rbac;
    }

    public String getContextID() throws PolicyContextException {
        return permissionScope.getScopeName();
    }

    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        for (Enumeration<Permission> e= permissions.elements(); e.hasMoreElements();) {
            addToRole(roleName, e.nextElement());
        }
    }

    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        //assure role
        RoleType role = roleScope.getRole(roleName);
        if (role == null) {
            role = new RoleType();
            role.setRoleName(roleName);
            roleScope.getRole().add(role);
        }
        //assure permission
        String permissionId = permissionScope.getScopeName() + ":" + permission.toString();
        PermissionType permissionType = null;
        for (PermissionType pt: permissionScope.getPermission()){
            if (permissionId.equals(pt.getPermissionId())) {
                permissionType = pt;
            }
        }

        if (permissionType == null) {
            permissionType = new PermissionType();
            permissionType.setClazz(permission.getClass().getName());
            permissionType.setName(permission.getName());
            permissionType.setActions(permission.getActions());
            permissionType.setPermissionId(permission.toString());
            permissionScope.getPermission().add(permissionType);
        }
        if (!role.getPermissionId().contains(permissionId)) {
            role.getPermissionId().add(permissionId);
        }
        //automap role?
    }

    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        for (Enumeration<Permission> e= permissions.elements(); e.hasMoreElements();) {
            addToRole(UNCHECKED_ROLE, e.nextElement());
        }
    }

    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        addToRole(UNCHECKED_ROLE, permission);
    }

    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
    }

    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
    }

    public void removeRole(String roleName) throws PolicyContextException {
        RoleType role = roleScope.getRole(roleName);
        if (role != null) {
            for (PermissionType pt: permissionScope.getPermission()) {
                role.getPermissionId().remove(pt.getPermissionId());
            }
/*
            if (!UNCHECKED_ROLE.equals(role.getRoleName()) && role.getPermissionId().isEmpty()) {
                roleScope.getRole().remove(role);
            }
*/
        }
    }

    public void removeUncheckedPolicy() throws PolicyContextException {
        removeRole(UNCHECKED_ROLE);
    }

    public void removeExcludedPolicy() throws PolicyContextException {
    }

    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
    }

    public void delete() {
        state = State.DELETED;
        //TODO does not take account of assigning permissions to other roles, not through JACC
        for (PermissionType pt: permissionScope.getPermission()) {
            String permissionId = pt.getPermissionId();
            for (RoleType role: roleScope.getRole()) {
                role.getPermissionId().remove(permissionId);
            }
        }
        permissionScope.getPermission().clear();
    }

    public void commit() throws PolicyContextException {
        rbac.commit(permissionScope);
        state = State.IN_SERVICE;
    }

    public boolean inService() {
        return state.inService;
    }

    public void open(boolean remove) {
        if (remove) {
            delete();
        }
        rbac.open(permissionScope);
        state = State.OPEN;
    }
}
