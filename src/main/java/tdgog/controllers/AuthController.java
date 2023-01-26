package tdgog.controllers;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Updates;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import spark.Route;
import tdgog.API;
import tdgog.mongo.MongoManager;
import static com.mongodb.client.model.Filters.eq;

import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthController {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();
    private static final MongoCollection<Document> userCollection = MongoManager.getDatabase().getCollection("users");

    /**
     * Generates random base64 encoded login token
     * @return token
     */
    private static String generateNewToken() {
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    static class RequestData {
        public String email;
        public String password;
    }

    static class ResponseData {
        public String token;

        ResponseData(String token) {
            this.token = token;
        }
    }

    static class TokenRequestData {
        public String email;
        public String token;
    }

    static class ErrorResponseData {
        public String error;

        public ErrorResponseData(String error) {
            this.error = error;
        }
    }

    /**
     * Checks if a string contains any of the characters in a second string
     * @param inputStr the string to check
     * @param characters the string containing all the characters to find
     * @return if the string contains any of the characters or not
     */
    private static boolean stringContainsAnyCharacter(String inputStr, String characters) {
        for(char character : characters.toCharArray())
            if(inputStr.contains(Character.toString(character)))
                return true;
        return false;
    }

    /**
     * Checks if the password provided is secure enough
     * @param password the password to check
     * @return whether the password is secure enough or not
     */
    private static boolean passwordValid(String password) {
        boolean symbol = stringContainsAnyCharacter(password, "!\"£$€%^&*(){}[]_+-=:;@'~#?/>.<,|\\");
        boolean lowercase = stringContainsAnyCharacter(password, "abcdefghijklmnopqrstuvwxyz");
        boolean uppercase = stringContainsAnyCharacter(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        boolean longEnough = password.length() >= 8;

        return symbol && lowercase && uppercase && longEnough;
    }

    /**
     * Checks if an email is in a valid format according to RFC 5322
     * @param email the email to check
     * @return whether the email is valid or not
     */
    private static boolean emailValid(String email) {
        Pattern pattern = Pattern.compile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(email);
        return matcher.find();
    }

    /**
     * Checks if the account already exists or not
     * @param email The account's email
     * @return Whether it exists or not
     */
    private static boolean accountAlreadyExists(String email) {
        Bson query = eq("email", email);
        long count = userCollection.countDocuments(query);
        return count >= 1;
    }

    /**
     * Hashes a string with the default settings and a preset cost
     * @param string the string to hash
     * @return the hashed string
     */
    private static String hashString(String string) {
        return BCrypt.withDefaults().hashToString(12, string.toCharArray());
    }

    private static Date getDateNextWeek() {
        Date currentDate = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.DATE, 14);

        return calendar.getTime();
    }

    /**
     * Adds an account to the database
     */
    public static Route addAccount = ((request, response) -> {
        RequestData signupRequestData = API.getGson().fromJson(request.body(), RequestData.class);

        if(accountAlreadyExists(signupRequestData.email)) {
            response.status(400);
            return new ErrorResponseData("AccountAlreadyExists");
        }

        if(!passwordValid(signupRequestData.password)) {
            response.status(400);
            return new ErrorResponseData("PasswordInvalid");
        }

        if(!emailValid(signupRequestData.email)) {
            response.status(400);
            return new ErrorResponseData("EmailInvalid");
        }

        String hash = hashString(signupRequestData.password);
        String token = generateNewToken();

        userCollection.insertOne(new Document()
                .append("_id", new ObjectId())
                .append("email", signupRequestData.email)
                .append("hashedPassword", hash)
                .append("loginToken", hashString(token))
                .append("tokenExpiry", getDateNextWeek())
        );

        response.status(200);
        return new ResponseData(token);
    });

    public static Route logIn = ((request, response) -> {
        RequestData loginRequestData = API.getGson().fromJson(request.body(), RequestData.class);

        Document user = userCollection.find(eq("email", loginRequestData.email)).first();
        if(user == null) {
            response.status(400);
            return new ErrorResponseData("NonexistentAccount");
        }

        String userHash = user.getString("hashedPassword");
        BCrypt.Result verificationResult = BCrypt.verifyer().verify(loginRequestData.password.toCharArray(), userHash);

        if(!verificationResult.verified) {
            response.status(400);
            return new ErrorResponseData("IncorrectPassword");
        }

        String token = generateNewToken();
        userCollection.updateOne(user, Updates.combine(
                Updates.set("loginToken", hashString(token)),
                Updates.set("tokenExpiry", getDateNextWeek())
        ));

        response.status(200);
        return new ResponseData(token);
    });

    public static Route logInWithToken = ((request, response) -> {
        TokenRequestData tokenRequestData = API.getGson().fromJson(request.body(), TokenRequestData.class);

        Document user = userCollection.find(eq("email", tokenRequestData.email)).first();
        if(user == null) {
            response.status(400);
            return new ErrorResponseData("NonexistentAccount");
        }

        String userHash = user.getString("loginToken");
        BCrypt.Result verificationResult = BCrypt.verifyer().verify(tokenRequestData.token.toCharArray(), userHash);
        if(!verificationResult.verified) {
            response.status(400);
            return new ErrorResponseData("IncorrectToken");
        }

        Date expiryDate = user.getDate("tokenExpiry");
        if(expiryDate.before(new Date())) {
            response.status(400);
            return new ErrorResponseData("ExpiredToken");
        }

        response.status(200);
        return null;
    });
}
