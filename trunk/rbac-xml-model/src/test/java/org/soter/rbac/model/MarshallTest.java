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
import java.io.Reader;
import java.io.InputStreamReader;
import java.io.Writer;
import java.io.StringWriter;
import java.io.StringReader;

import org.testng.annotations.Test;
import org.apache.geronimo.testsupport.DOMUtils;
import org.w3c.dom.Document;

/**
 * @version $Rev:$ $Date:$
 */
@Test
public class MarshallTest {

    @Test
    public void testFromXml() throws Exception {
        InputStream in = getClass().getClassLoader().getResourceAsStream("test-rbac.xml");
        Reader reader = new InputStreamReader(in);
        Writer out1 = new StringWriter();
        char[] buf = new char[1024];
        int i;
        while ((i = reader.read(buf)) > 0) {
            out1.write(buf, 0, i);
        }
        reader.close();
        String s1 = out1.toString();
        reader = new StringReader(s1);
        RbacType rbac = RbacXmlUtil.loadRbac(reader);
        Writer out = new StringWriter();
        RbacXmlUtil.writeRbac(rbac, out);
        String s2 = out.toString();
        Document d1 = DOMUtils.load(s1);
        Document d2 = DOMUtils.load(s2);
        DOMUtils.compareNodes(d1, d2);
    }
}
