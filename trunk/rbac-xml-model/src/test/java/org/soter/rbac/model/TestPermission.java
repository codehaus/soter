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


package org.soter.rbac.model;

import java.security.Permission;
import org.apache.xbean.recipe.ParameterNames;

/**
 * @version $Rev:$ $Date:$
 */
public class TestPermission extends Permission {

    private final String actions;
    /**
     * Constructs a permission with the specified name.
     *
     * @param name name of the Permission object being created.
     */
    @ParameterNames({"name", "actions"})
    public TestPermission(String name, String actions) {
        super(name);
        if (name == null) {
            throw new NullPointerException("name required");
        }
        this.actions = actions;
    }

    public boolean implies(Permission permission) {
        return equals(permission);
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TestPermission that = (TestPermission) o;

        if (!getName().equals(that.getName())) return false;
        if (actions != null ? !actions.equals(that.actions) : that.actions != null) return false;

        return true;
    }

    public int hashCode() {
        return getName().hashCode() ^ (actions != null ? actions.hashCode() : 0);
    }

    public String getActions() {
        return actions;
    }
}
