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

import java.io.Writer;
import java.io.Reader;
import java.io.IOException;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;
import org.soter.rbac.model.RbacType;
import org.soter.rbac.model.ObjectFactory;

/**
 * @version $Rev:$ $Date:$
 */
public class RbacXmlUtil {
    public static final XMLInputFactory XMLINPUT_FACTORY = XMLInputFactory.newInstance();
    public static final JAXBContext RBAC_CONTEXT;

    static {
        try {
            RBAC_CONTEXT = JAXBContext.newInstance(RbacType.class);
        } catch (JAXBException e) {
            throw new RuntimeException("Could not create jaxb contexts for plugin types");
        }
    }

    public static void writeRbac(RbacType metadata, Writer out) throws XMLStreamException, JAXBException {
        Marshaller marshaller = RBAC_CONTEXT.createMarshaller();
        marshaller.setProperty("jaxb.formatted.output", true);
        JAXBElement<RbacType> element = new ObjectFactory().createRbac(metadata);
        marshaller.marshal(element, out);
    }


    public static RbacType loadRbac(Reader in) throws ParserConfigurationException, IOException, SAXException, JAXBException, XMLStreamException {
        XMLStreamReader xmlStream = XMLINPUT_FACTORY.createXMLStreamReader(in);
        return loadRbac(xmlStream);
    }

    public static RbacType loadRbac(XMLStreamReader in) throws ParserConfigurationException, IOException, SAXException, JAXBException, XMLStreamException {
        Unmarshaller unmarshaller = RBAC_CONTEXT.createUnmarshaller();
        JAXBElement<RbacType> element = unmarshaller.unmarshal(in, RbacType.class);
        RbacType rbac = element.getValue();
        return rbac;
    }

}
