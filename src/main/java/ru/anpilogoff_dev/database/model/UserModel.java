package ru.anpilogoff_dev.database.model;

import jakarta.validation.constraints.Pattern;
import lombok.*;


/**
 * Класс модели данных пользователя, используемая для регистрации и управления учетными записями.
 */
@Getter
@Setter
@EqualsAndHashCode
@NoArgsConstructor
@ToString
public class UserModel {
    private long id;

    @Pattern(regexp = "^[a-zA-Z0-9_]{7,15}$",
            message = "Invalid login value, must between 4 - 15")
    private String login;

    @Pattern(regexp = "^(?=.*[A-Z])(?=.*\\d)[A-Za-z\\d]{8,}$",
            message = "Invalid password value, must be at least 8 characters long," +
                    "contain at least one capital letter and one number.")
    private String password;

    @Pattern(regexp = "^[a-zA-Z0-9]{1,20}@[a-zA-Z0-9]{1,15}\\.[a-zA-Z0-9]{1,10}$", message = "Invalid email value")
    private String email;

    private String nickname;

    private String registrationDate; //пока не решил нужно ли.....


    public UserModel(String login, String password, String email, String nickname) {
        this.login = login;
        this.password = password;
        this.email = email;
        this.nickname = nickname;
    }

    public UserModel(String login) {
        this.login = login;
    }
}
