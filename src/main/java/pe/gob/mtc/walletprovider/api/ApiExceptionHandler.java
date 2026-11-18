package pe.gob.mtc.walletprovider.api;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import pe.gob.mtc.walletprovider.api.ApiModels.ErrorResponse;
import java.security.GeneralSecurityException;
import java.util.NoSuchElementException;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler({SecurityException.class,GeneralSecurityException.class})
    public ResponseEntity<ErrorResponse> rejected(Exception e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("ATTESTATION_REJECTED","Security evidence rejected"));
    }
    @ExceptionHandler({IllegalArgumentException.class,org.springframework.web.bind.MethodArgumentNotValidException.class})
    public ResponseEntity<ErrorResponse> badRequest(Exception e) {
        return ResponseEntity.badRequest().body(new ErrorResponse("INVALID_REQUEST","Request is invalid"));
    }
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ErrorResponse> notFound(Exception e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("NOT_FOUND","Resource not found"));
    }
}
