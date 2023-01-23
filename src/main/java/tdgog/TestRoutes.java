package tdgog;

import spark.Route;

record MyMessage(String text) { }

public class TestRoutes {

    public static Route helloJSON = ((request, response) -> {
        return new MyMessage("Hello, world!");
    });

}
