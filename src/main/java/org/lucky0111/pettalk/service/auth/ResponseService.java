package org.lucky0111.pettalk.service.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public interface ResponseService {
    ResponseEntity<?> createSuccessResponse(Object data, String message);
    ResponseEntity<?> createSuccessResponse(Object data, String message, HttpStatus status);
    ResponseEntity<?> createErrorResponse(String code, String message);
    ResponseEntity<?> createErrorResponse(String code, String message, HttpStatus httpStatus);
}