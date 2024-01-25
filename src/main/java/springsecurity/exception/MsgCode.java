package springsecurity.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum MsgCode {

    OOPS_ERROR(500, "oops-error"),

    ;

    private final Integer code;
    private final String languageKey;
}