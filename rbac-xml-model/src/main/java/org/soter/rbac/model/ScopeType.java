//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.0.3-b01-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2008.03.26 at 04:26:50 PM PDT 
//


package org.soter.rbac.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for scopeType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="scopeType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="scope-name" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="classloader-name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="role" type="{http://geronimo.apache.org/xml/ns/rbac-xml}roleType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="permission" type="{http://geronimo.apache.org/xml/ns/rbac-xml}permissionType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="scope" type="{http://geronimo.apache.org/xml/ns/rbac-xml}scopeType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "scopeType", propOrder = {
        "scopeName",
        "classloaderName",
        "role",
        "permission",
        "scope"
        })
public class ScopeType
        implements Serializable, Keyable<String> {

    private final static long serialVersionUID = 12343L;
    @XmlElement(name = "scope-name", required = true)
    protected String scopeName;
    @XmlElement(name = "classloader-name")
    protected String classloaderName;
    private final KeyedCollection<String, RoleType> role = new KeyedCollection<String, RoleType>();
    private final KeyedCollection<String, PermissionType> permission = new KeyedCollection<String, PermissionType>();
    private final KeyedCollection<String, ScopeType> scope = new KeyedCollection<String, ScopeType>();

    @XmlTransient
    private final Map<String, PermissionType> permissions = new HashMap<String, PermissionType>();
    @XmlTransient
    private ScopeType parentScope;
    @XmlTransient
    private Map<String, ScopeType> descendantScopes = new HashMap<String, ScopeType>();
    @XmlTransient
    private final Map<String, RoleType> roles = new HashMap<String, RoleType>();


    public ScopeType() {
    }

    public ScopeType(ScopeType original, ScopeType parent) {
        scopeName = original.scopeName;
        classloaderName = original.classloaderName;
        //TODO these are iffy.  They are no longer the same objects as in the maps.
        role.addAll(original.role);
        permission.addAll(original.permission);
        scope.addAll(original.scope);

        parentScope = parent;

        descendantScopes.put(scopeName, this);
        for (Map.Entry<String, ScopeType> s: original.descendantScopes.entrySet()) {
            if (!descendantScopes.containsKey(s.getKey())) {
                ScopeType copy = new ScopeType(s.getValue(), this);
                permissions.putAll(copy.permissions);
                descendantScopes.putAll(copy.descendantScopes);
            }
        }
        for (Map.Entry<String, PermissionType> p: original.permissions.entrySet()) {
            if (!permissions.containsKey(p.getKey())) {
                permissions.put(p.getKey(), new PermissionType(p.getValue(), this));
            }
        }
        for (Map.Entry<String, RoleType> r: original.roles.entrySet()) {
            roles.put(r.getKey(), new RoleType(r.getValue(), this));
        }
    }

    /**
     * Gets the value of the scopeName property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getScopeName() {
        return scopeName;
    }

    public String getKey() {
        return getScopeName();
    }

    /**
     * Sets the value of the scopeName property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setScopeName(String value) {
        this.scopeName = value;
    }

    /**
     * Gets the value of the classloaderName property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getClassloaderName() {
        return classloaderName;
    }

    /**
     * Sets the value of the classloaderName property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setClassloaderName(String value) {
        this.classloaderName = value;
    }

    /**
     * Gets the value of the role property.
     * <p/>
     * <p/>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the role property.
     * <p/>
     * <p/>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRole().add(newItem);
     * </pre>
     * <p/>
     * <p/>
     * <p/>
     * Objects of the following type(s) are allowed in the list
     * {@link RoleType }
     */
    public Collection<RoleType> getRole() {
        return role;
    }

    /**
     * Gets the value of the permission property.
     * <p/>
     * <p/>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the permission property.
     * <p/>
     * <p/>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPermission().add(newItem);
     * </pre>
     * <p/>
     * <p/>
     * <p/>
     * Objects of the following type(s) are allowed in the list
     * {@link PermissionType }
     */
    public Collection<PermissionType> getPermission() {
        return permission;
    }

    /**
     * Gets the value of the scope property.
     * <p/>
     * <p/>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the scope property.
     * <p/>
     * <p/>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getScope().add(newItem);
     * </pre>
     * <p/>
     * <p/>
     * <p/>
     * Objects of the following type(s) are allowed in the list
     * {@link ScopeType }
     */
    public Collection<ScopeType> getScope() {
        return scope;
    }

    public Map<String, PermissionType> getPermissions() {
        return permissions;
    }

    public ScopeType getParentScope() {
        return parentScope;
    }

    public Map<String, ScopeType> getDescendantScopes() {
        return descendantScopes;
    }

    public void start(ScopeType parentScope, ClassLoader cl, ClassLoaderLookup clLookup, Map<String, ScopeType> scopes) {
        if (classloaderName != null) {
            cl = clLookup.getClassLoader(classloaderName);
        }
        this.parentScope = parentScope;
        descendantScopes.put(getScopeName(), this);
        scopes.put(getScopeName(), this);
        if (scope != null) {
            for (ScopeType child : scope) {
                child.start(this, cl, clLookup, scopes);
                permissions.putAll(child.getPermissions());
                descendantScopes.putAll(child.getDescendantScopes());
            }
        }
        if (permission != null) {
            for (PermissionType permissionType : permission) {
                permissionType.start(this, cl);
                permissions.put(permissionType.getPermissionId(), permissionType);
            }
        }
        if (role != null) {
            for (RoleType role : this.role) {
                role.startPermissions(this);
                roles.put(role.getRoleName(), role);
            }
            for (RoleType role : this.role) {
                role.startSubRoles(this);
            }
        }
    }

    public RoleType getRole(RoleRefType ref) {
        ScopeType scope = descendantScopes.get(ref.getScopeName());
        if (scope == null) {
            throw new NullPointerException("No scope named: " + ref.getScopeName());
        }
        return scope.getRole(ref.getRoleName());
    }

    public RoleType getRole(String roleName) {
        RoleType role = roles.get(roleName);
        if (role == null) {
            throw new NullPointerException("No role found in scope " + getScopeName() + " with name " + roleName);
        }
        return role;
    }


    public void mergeModel(ScopeType bit) {
        if (!getScopeName().equals(bit.getScopeName())) {
            throw new IllegalArgumentException("Mismatched merge: this is named " + getScopeName() + ", trying to merge: " + bit.getScopeName());
        }
        for (ScopeType childScope : bit.getScope()) {
            String childScopeName = childScope.getScopeName();
            ScopeType existingChildScope = getDescendantScopes().get(childScopeName);
            if (existingChildScope == null) {
                getScope().add(childScope);
            } else {
                existingChildScope.mergeModel(childScope);
            }
        }
        for (PermissionType p : bit.getPermission()) {
            if (getPermissions().containsKey(p.getPermissionId())) {
                throw new IllegalArgumentException("Duplicate permission: " + p);
            }
            getPermission().add(p);
        }
        for (RoleType role : bit.getRole()) {
            RoleType existingRole = roles.get(role.getRoleName());
            if (existingRole == null) {
                getRole().add(role);
            } else {
                existingRole.mergeModel(role);
            }
        }
    }

    public void merge(ScopeType bit) {
        if (!getScopeName().equals(bit.getScopeName())) {
            throw new IllegalArgumentException("Mismatched merge: this is named " + getScopeName() + ", trying to merge: " + bit.getScopeName());
        }
        for (ScopeType childScope : bit.getScope()) {
            String childScopeName = childScope.getScopeName();
            ScopeType existingChildScope = getDescendantScopes().get(childScopeName);
            if (existingChildScope != null) {
                existingChildScope.merge(childScope);
            }
            permissions.putAll(childScope.getPermissions());
            descendantScopes.putAll(childScope.getDescendantScopes());
        }
        for (PermissionType p : bit.getPermission()) {
            if (getPermissions().containsKey(p.getPermissionId())) {
                throw new IllegalArgumentException("Duplicate permission: " + p);
            }
            getPermissions().put(p.getPermissionId(), p);
        }
        for (RoleType role : bit.getRole()) {
            RoleType existingRole = roles.get(role.getRoleName());
            if (existingRole == null) {
                roles.put(role.getRoleName(), role);
            }
        }
        for (RoleType role : bit.getRole()) {
            RoleType existingRole = roles.get(role.getRoleName());
            existingRole.merge(role, this);
        }
    }

    public void mergeData(ScopeType bit) {
        if (!getScopeName().equals(bit.getScopeName())) {
            throw new IllegalArgumentException("Mismatched merge: this is named " + getScopeName() + ", trying to merge: " + bit.getScopeName());
        }
        if (classloaderName == null) {
            classloaderName = bit.classloaderName;
        }

        for (RoleType role : bit.role) {
            RoleType existingRole = this.role.toMap().get(role.getRoleName());
            if (existingRole != null) {
                existingRole.mergeModel(role);
            } else {
                this.role.add(role);
            }
        }

        for (ScopeType scope : bit.scope) {
            ScopeType existingScope = this.scope.toMap().get(scope.getScopeName());
            if (existingScope != null) {
                existingScope.mergeModel(scope);
            } else {
                this.scope.add(scope);
            }
        }

        for (PermissionType permission: bit.permission) {
            if (this.permission.toMap().containsKey(permission.getPermissionId())) {
                throw new IllegalStateException("Permission already registered with id " + permission.getPermissionId());
            }
            this.permission.add(permission);
        }
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ScopeType scopeType = (ScopeType) o;

        if (classloaderName != null ? !classloaderName.equals(scopeType.classloaderName) : scopeType.classloaderName != null) return false;
        if (scopeName != null ? !scopeName.equals(scopeType.scopeName) : scopeType.scopeName != null) return false;
        if (permission != null ? !new HashSet<PermissionType>(permission).equals(new HashSet<PermissionType>(scopeType.getPermission())) : scopeType.permission != null) return false;
        if (role != null ? !new HashSet<RoleType>(role).equals(new HashSet<RoleType>(scopeType.getRole())) : scopeType.role != null) return false;
        if (scope != null ? !new HashSet<ScopeType>(scope).equals(new HashSet<ScopeType>(scopeType.getScope())) : scopeType.scope != null) return false;

        return true;
    }

    public int hashCode() {
        int result;
        result = (scopeName != null ? scopeName.hashCode() : 0);
        result = 31 * result + (classloaderName != null ? classloaderName.hashCode() : 0);
        result = 31 * result + (role != null ? role.hashCode() : 0);
        result = 31 * result + (permission != null ? permission.hashCode() : 0);
        result = 31 * result + (scope != null ? scope.hashCode() : 0);
        result = 31 * result + (permissions != null ? permissions.hashCode() : 0);
        result = 31 * result + (parentScope != null ? parentScope.hashCode() : 0);
        result = 31 * result + (descendantScopes != null ? descendantScopes.hashCode() : 0);
        result = 31 * result + (roles != null ? roles.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("ScopeType:").append(System.identityHashCode(this));
        b.append(": name: ").append(scopeName);
        return b.toString();
    }

}
