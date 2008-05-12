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


package org.soter.rbac;

import java.io.InputStream;
import java.io.Reader;
import java.io.InputStreamReader;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.testng.annotations.Test;
import org.soter.rbac.model.RbacType;
import org.soter.rbac.model.RbacXmlUtil;
import org.soter.rbac.model.TestPermission;
import org.xml.sax.SAXException;

/**
 * @version $Rev:$ $Date:$
 */
@Test
public class XmlSecurityServiceTest {
    
    @Test
    public void testXmlSecurityService() throws Exception {
        String file = "test-rbac.xml";
        RbacType rbac = loadRbac(file);
        XmlSecurityService ss = new XmlSecurityService(rbac);
        checkFred(ss);
    }

    private void checkFred(XmlSecurityService ss) throws Exception {
        if (ss.check(new UserInfo("fred", "fred"), new TestPermission("p1", "foo"), "global")) throw new Exception("fred does have p1");
        if (ss.check(new UserInfo("fred", "fred"), new TestPermission("p2", "bar"), "global")) throw new Exception("fred does have p2");
        if (!ss.check(new UserInfo("fred", "fred"), new TestPermission("p3", "foo"), "global")) throw new Exception("fred does not have p3");
        if (!ss.check(new UserInfo("fred", "fred"), new TestPermission("p4", "bar"), "global")) throw new Exception("fred does not have p4");
    }

    private RbacType loadRbac(String file) throws ParserConfigurationException, IOException, SAXException, JAXBException, XMLStreamException {
        InputStream in = getClass().getClassLoader().getResourceAsStream(file);
        Reader reader = new InputStreamReader(in);
        RbacType rbac = RbacXmlUtil.loadRbac(reader);
        rbac.start(getClass().getClassLoader(), null);
        return rbac;
    }

    @Test
    public void testMergeModel() throws Exception {
        RbacType big = loadRbac("test-rbac-big.xml");
//        RbacType user = loadRbac("test-rbac-user.xml");
        RbacType app = loadRbac("test-rbac-app.xml");
        big.mergeModel(app);
//        big.merge(user);
        big.start(getClass().getClassLoader(), null);
        XmlSecurityService ss = new XmlSecurityService(big);
        checkFred(ss);
    }
    
    @Test
    public void testMerge() throws Exception {
        RbacType big = loadRbac("test-rbac-big.xml");
//        RbacType user = loadRbac("test-rbac-user.xml");
        RbacType app = loadRbac("test-rbac-app.xml");
        big.merge(app);
//        big.merge(user);
        big.start(getClass().getClassLoader(), null);
        XmlSecurityService ss = new XmlSecurityService(big);
        checkFred(ss);
    }
}
