package com.demo.Authentication.config;

import java.util.List;

public class LoggedInUserContext {

    private static final ThreadLocal<String> USER_CONTEXT = new ThreadLocal<>();

    private static final ThreadLocal<List<String>> USER_CONTEXT_ROLES = new ThreadLocal<>();


    public static void setLoggedInUser(String userId) {
        USER_CONTEXT.set(userId);
    }

    public static void setLoggedInUserRoles(List<String> roles) {
        USER_CONTEXT_ROLES.set(roles);
    }


    public static String getLoggedInUserName() {
        return USER_CONTEXT.get();
    }

    public static List<String> getCurrentUserRoles() {
        return USER_CONTEXT_ROLES.get();
    }


    public static void clear() {
        USER_CONTEXT.remove();
    }

}
