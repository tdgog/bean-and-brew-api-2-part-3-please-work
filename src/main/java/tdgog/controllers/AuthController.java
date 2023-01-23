package tdgog.controllers;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.bson.Document;
import org.bson.types.ObjectId;
import spark.Route;
import tdgog.API;
import tdgog.mongo.MongoManager;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthController {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();

    private static String generateNewToken() {
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    static class SignupRequestData {
        public String email;
        public String password;
    }

    static class SignupResponseData {
        public String token;

        SignupResponseData(String token) {
            this.token = token;
        }
    }

    private static boolean stringContainsAnyCharacter(String inputStr, String characters) {
        for(char character : characters.toCharArray())
            if(inputStr.contains(Character.toString(character)))
                return true;
        return false;
    }

    private static boolean passwordValid(String password) {
        boolean symbol = stringContainsAnyCharacter(password, "!\"£$€%^&*(){}[]_+-=:;@'~#?/>.<,|\\");
        boolean lowercase = stringContainsAnyCharacter(password, "abcdefghijklmnopqrstuvwxyz");
        boolean uppercase = stringContainsAnyCharacter(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        boolean longEnough = password.length() >= 8;

        return symbol && lowercase && uppercase && longEnough;
    }

    private static boolean emailValid(String email) {
        Pattern pattern = Pattern.compile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(email);
        return matcher.find();
    }

    private static boolean accountAlreadyExists(String email) {
        return false;
    }

    public static Route addAccount = ((request, response) -> {
        SignupRequestData signupRequestData = API.getGson().fromJson(request.body(), SignupRequestData.class);

        if(accountAlreadyExists(signupRequestData.email)) {
            response.status(400);
            return null;
        }

        if(!passwordValid(signupRequestData.password) || !emailValid(signupRequestData.email)) {
            response.status(400);
            return null;
        }

        String hash = BCrypt.withDefaults().hashToString(12, signupRequestData.password.toCharArray());
        String token = generateNewToken();

        MongoManager.getDatabase().getCollection("users").insertOne(new Document()
                .append("_id", new ObjectId())
                .append("email", signupRequestData.email)
                .append("hashedPassword", hash)
                .append("loginToken", token)
        );

        response.status(200);
        return new SignupResponseData(token);
    });

}
