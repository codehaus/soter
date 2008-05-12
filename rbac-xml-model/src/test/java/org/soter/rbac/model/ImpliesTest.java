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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.testng.annotations.Test;

/**
 * @version $Rev:$ $Date:$
 */
@Test
public class ImpliesTest {

    private static final TestPermission p1 = new TestPermission("p1", "foo");
    private static final TestPermission p2 = new TestPermission("p2", "bar");
    private static final TestPermission p3 = new TestPermission("p3", "foo");
    private static final TestPermission p4 = new TestPermission("p4", "bar");
    private static final TestPermission p5 = new TestPermission("p5", "foo");

    private  static final List<TestPermission> all = Arrays.asList(p1, p2, p3, p4, p5);

    @Test
    public void testFromXml() throws Exception {
        InputStream in = getClass().getClassLoader().getResourceAsStream("test-rbac.xml");
        Reader reader = new InputStreamReader(in);
        RbacType rbac = RbacXmlUtil.loadRbac(reader);
        rbac.start(getClass().getClassLoader(), null);
        checkPermissions(rbac);
        checkPermissions(new RbacType(rbac));
    }

    private void checkPermissions(RbacType rbac) throws Exception {
        check(rbac, "role1", "global", p1, p2, p3, p4);
        check(rbac, "role2", "app1", p2, p4);
        check(rbac, "role3", "app1", p3);
        check(rbac, "role4", "app1", p4);
    }

    private void check(RbacType rbac, String roleName, String scopeName, TestPermission... ps) throws Exception {
        RoleType role = rbac.getRole(new RoleRefType(roleName, scopeName));
        Set<TestPermission> all = new HashSet(this.all);
        for (TestPermission p: ps) {
            all.remove(p);
            if (!role.implies(p, "global")) throw new Exception(p.toString() + "not implied in global scope with " + roleName);
            if (!role.implies(p, "app1")) throw new Exception(p.toString() + "not implied in app1 scope with " + roleName);
        }
        for (TestPermission p: all) {
            if (role.implies(p, "global")) throw new Exception(p.toString() + " implied in global scope with " + roleName);
            if (role.implies(p, "app1")) throw new Exception(p.toString() + " implied in app1 scope with " + roleName);
        }
    }

}
