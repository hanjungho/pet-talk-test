package org.lucky0111.pettalk.util.auth;

import lombok.experimental.UtilityClass;

@UtilityClass
public class StringUtils {
    public static boolean isNotEmpty(String str) {
        return str != null && !str.isBlank();
    }

    public static boolean isEmpty(String str) {
        return str == null || str.isBlank();
    }
}