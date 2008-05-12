//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.0.3-b01-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2008.03.26 at 04:26:50 PM PDT 
//


package org.soter.rbac.model;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for role-refType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="role-refType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="role-name" type="{http://www.w3.org/2001/XMLSchema}anySimpleType" />
 *       &lt;attribute name="scope-name" type="{http://www.w3.org/2001/XMLSchema}anySimpleType" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "role-refType")
public class RoleRefType
    implements Serializable
{

    private final static long serialVersionUID = 12343L;
    @XmlAttribute(name = "role-name")
    protected String roleName;
    @XmlAttribute(name = "scope-name")
    protected String scopeName;

    public RoleRefType() {
    }

    public RoleRefType(String roleName, String scopeName) {
        this.roleName = roleName;
        this.scopeName = scopeName;
    }

    /**
     * Gets the value of the roleName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRoleName() {
        return roleName;
    }

    /**
     * Sets the value of the roleName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRoleName(String value) {
        this.roleName = value;
    }

    /**
     * Gets the value of the scopeName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getScopeName() {
        return scopeName;
    }

    /**
     * Sets the value of the scopeName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setScopeName(String value) {
        this.scopeName = value;
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RoleRefType that = (RoleRefType) o;

        if (roleName != null ? !roleName.equals(that.roleName) : that.roleName != null) return false;
        if (scopeName != null ? !scopeName.equals(that.scopeName) : that.scopeName != null) return false;

        return true;
    }

    public int hashCode() {
        int result;
        result = (roleName != null ? roleName.hashCode() : 0);
        result = 31 * result + (scopeName != null ? scopeName.hashCode() : 0);
        return result;
    }
}
