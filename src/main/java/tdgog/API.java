package tdgog;

import com.google.gson.Gson;
import spark.Filter;
import tdgog.controllers.AuthController;
import tdgog.transformers.JsonTransformer;

import static spark.Spark.*;

public class API {

    private static Gson gson = new Gson();

    public static void main(String[] args) {
        // Avoid CORS
        after((Filter) (request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Allow-Methods", "GET");
        });

        get("/hello", (req, res) -> "Hello World");
        get("/hellojson", "application/json", TestRoutes.helloJSON, new JsonTransformer());

        post("/addAccount", "application/json", AuthController.addAccount, new JsonTransformer());
    }

    public static Gson getGson() {
        return gson;
    }
}
