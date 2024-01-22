package com.demo.Authentication.service;


import org.springframework.ldap.core.LdapTemplate;

import javax.naming.Name;
import java.util.List;

public interface LdapRepositoryService {

    public List<String> getRoleNamesFromLdap(String uid, String groupName, LdapTemplate ldapTemplete);

}
