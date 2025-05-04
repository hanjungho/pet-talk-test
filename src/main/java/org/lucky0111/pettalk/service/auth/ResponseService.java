package org.lucky0111.pettalk.service.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public interface ResponseService {
    /**
     * 성공 응답을 생성합니다.
     *
     * @param data    응답 데이터
     * @param message 성공 메시지
     * @return 표준화된 성공 응답
     */
    ResponseEntity<?> createSuccessResponse(Object data, String message);

    /**
     * 성공 응답을 생성합니다 (상태 코드 지정).
     *
     * @param data    응답 데이터
     * @param message 성공 메시지
     * @param status  HTTP 상태 코드
     * @return 표준화된 성공 응답
     */
    ResponseEntity<?> createSuccessResponse(Object data, String message, HttpStatus status);

    /**
     * 오류 응답을 생성합니다.
     *
     * @param code    오류 코드
     * @param message 오류 메시지
     * @return 표준화된 오류 응답
     */
    ResponseEntity<?> createErrorResponse(String code, String message);

    /**
     * 오류 응답을 생성합니다 (상태 코드 지정).
     *
     * @param code       오류 코드
     * @param message    오류 메시지
     * @param httpStatus HTTP 상태 코드
     * @return 표준화된 오류 응답
     */
    ResponseEntity<?> createErrorResponse(String code, String message, HttpStatus httpStatus);
}

