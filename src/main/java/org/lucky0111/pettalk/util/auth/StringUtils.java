package org.lucky0111.pettalk.util.auth;

import lombok.experimental.UtilityClass;

@UtilityClass
public class StringUtils {
    /**
     * 문자열이 null이 아니고 비어있지 않은지 확인합니다.
     *
     * @param str 확인할 문자열
     * @return null이 아니고 비어있지 않으면 true, 그렇지 않으면 false
     */
    public static boolean isNotEmpty(String str) {
        return str != null && !str.isBlank();
    }

    /**
     * 문자열이 null이거나 비어있는지 확인합니다.
     *
     * @param str 확인할 문자열
     * @return null이거나 비어있으면 true, 그렇지 않으면 false
     */
    public static boolean isEmpty(String str) {
        return str == null || str.isBlank();
    }
}