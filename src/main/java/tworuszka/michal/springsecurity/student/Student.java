package tworuszka.michal.springsecurity.student;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@ToString
@AllArgsConstructor
@Getter
public class Student {

    private final Integer studentId;
    private final String studentName;

}
