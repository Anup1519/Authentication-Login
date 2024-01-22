package com.demo.Authentication.repo;

import com.demo.Authentication.config.LdapConfig;
import com.demo.Authentication.service.LdapRepositoryService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.stereotype.Component;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@SuppressWarnings("deprecation")
@Component
public class LdapRepositoryServiceImpl implements LdapRepositoryService {

    @Autowired
    private LdapConfig ldapConstant;
    @Override
    public List<String> getRoleNamesFromLdap(String uid, String groupName, LdapTemplate ldapTempleteInternal) {
    if (groupName != null && !groupName.isEmpty()) {
        String searchFilter = "(&(objectclass=" + ldapConstant.userGroupObjectClass + ")("
                + ldapConstant.groupMemberAttribute + "=" + ldapConstant.userNameAttribute + "=" + uid + "," + LdapConfig.NLPGROUP + "="
                + groupName + "," + ldapConstant.internalLdapBase + "))";
        return ldapTempleteInternal.search(LdapConfig.NLPGROUP + "=" + LdapConfig.NLPROLEBASEOU, searchFilter,
                (AttributesMapper<String>) attrs -> (String) attrs.get(ldapConstant.groupNameAttribute)
                        .get());
    } else {
        List<String> userRoles = new LinkedList<String>();
        List<String> userRolesInLdap = ldapTempleteInternal.search(
                query().where("objectclass").is(ldapConstant.userGroupObjectClass)
                        .and(query().where(LdapConfig.NLPGROUP).is(LdapConfig.NLPROLEBASEOU)),
                (AttributesMapper<String>) attrs -> {
                    String userRole = "";
                    for (int i = 0; i < attrs.get(ldapConstant.groupMemberAttribute).size(); i++) {
                        if (attrs.get(ldapConstant.groupMemberAttribute).get(i) != null && !attrs.get(ldapConstant.groupMemberAttribute).get(i).toString().trim().isEmpty()) {
                            if (attrs.get(ldapConstant.groupMemberAttribute).get(i).toString().indexOf(ldapConstant.userNameAttribute + "=" + uid) >= 0) {
                                userRole = attrs.get(ldapConstant.groupNameAttribute).toString();
                                if (userRole.toLowerCase().startsWith("cn:") || userRole.toLowerCase().startsWith("uid:")) {
                                    userRole = userRole.split(":")[1].trim();
                                }
                            }
                        }
                    }
                    return userRole;
                });
        userRolesInLdap.forEach(role -> {
            if (role != null && !role.trim().isEmpty()) userRoles.add(role);
        });
        return userRoles;
    }
}



}
