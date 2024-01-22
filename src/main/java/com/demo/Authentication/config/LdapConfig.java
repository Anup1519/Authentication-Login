package com.demo.Authentication.config;

import com.demo.Authentication.utills.SecurityUtils;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;

@Data
@Configuration
public class LdapConfig {


    @Value("${nlp.ldap.base.ou:null}")
    public String ldapOU;
    @Value("${nlp.ldap.base.dn:null}")
    public String internalLdapBase;
    @Value("${nlp.ldap.url:null}")
    public String internalLdapUrl;
    @Value("${nlp.ldap.ldapbindpassword:null}")
    public String internalPassword;
    @Value("${nlp.ldap.binddn:null}")
    public String internalDirBindDn;
    @Value("${nlp.ldap.user.nameAttribute:null}")
    public String userNameAttribute;
    @Value("${nlp.ldap.user.objectclass:null}")
    public String userObjectClass;
    @Value("${nlp.ldap.user.group.object.class:null}")
    public String userGroupObjectClass;
    @Value("${nlp.ldap.group.memberattribute:null}")
    public String groupMemberAttribute;
    @Value("${nlp.ldap.group.nameAttribute:null}")
    public String groupNameAttribute;
    @Value("${nlp.directory.sync.source:null}")
    public String directorySyncSource;
    @Value("${nlp.ldap.userDnPattern:null}")
    public String userDnPattern;




    public final static String LDAPAUTHENTICATION = "simple";
    public final static String NLPROLEBASEOU = "NLPRoles";

    public final static String NLPGROUP = "ou";
    public final static String OBJECTCLASSFORGROUPORGANUNIT = "organizationalunit";
    public final static String OBJECTCLASSFORUSERTOP = "top";
    public final static String OBJECTCLASSFORUSERPERSON = "person";
    public final static String OBJECTCLASSFORUSERUID = "uidObject";
    public final static String OBJECTCLASSFORUSEROP = "organizationalPerson";
    public final static String OBJECTCLASSFORUSERINETORG = "inetOrgPerson";
    public final static String OBJECTCLASSFORGROUPGROUPOFUN = "groupOfUniqueNames";
    public final static String USERATTRIBUTESN = "sn";
    /*Following variable defines hierarchy of objects for a person object in LDAP*/
    public static final String[] personObjects = {"top", "person", "organizationalPerson", "inetOrgPerson"};
    /*Following 2 variable declare Ldap Object class for user Groups (2 possible types i.e. groupOfNames or groupOfUniqueNames*/
    public static final String USER_GROUP_OBJECT_CLASS_NAMES = "groupOfNames";
    public static final String USER_GROUP_OBJECT_CLASS_UNIQUENAMES = "groupOfUniqueNames";
    //following is the object type for user group in AD
    public static final String AD_USER_GROUP_OBJECT_CLASS = "group";




    @Bean
    public LdapContextSource ldapContextSource () throws Exception {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(internalLdapUrl);
        contextSource.setBase(internalLdapBase);
        contextSource.setUserDn(internalDirBindDn);
        contextSource.setPassword(SecurityUtils.aesDecrypt(internalPassword));
        contextSource.setPooled(true);
        contextSource.afterPropertiesSet();
        return contextSource;

    }


}
