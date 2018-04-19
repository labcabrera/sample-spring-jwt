package org.lab.sample.jwt.web;

import org.lab.sample.jwt.web.model.ErrorResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import lombok.extern.slf4j.Slf4j;

@ControllerAdvice
@Slf4j
public class ApplicationExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler({ RuntimeException.class })
	protected ResponseEntity<Object> handleInvalidRequest(RuntimeException ex, WebRequest request) {
		log.error("Processing error", ex);

		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String message = ex.getMessage();
		String code = String.valueOf(status.ordinal());

		if (AccessDeniedException.class.isAssignableFrom(ex.getClass())) {
			status = HttpStatus.FORBIDDEN;
		}

		ErrorResource error = new ErrorResource(code, message);
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return handleExceptionInternal(ex, error, headers, status, request);
	}

}