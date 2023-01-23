package tdgog.mongo;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;
import org.bson.Document;

public class MongoManager {

    private static final MongoClient client = new MongoClient("localhost", 27017);
    private static final MongoDatabase database = client.getDatabase("bean-and-brew-part-3-the-second-one");

    private static MongoCollection<Document> createCollectionIfNotExists(String collectionName) {
        if(!collectionExists(collectionName))
            database.createCollection(collectionName);
        return database.getCollection(collectionName);
    }

    private static boolean collectionExists(String collectionName) {
        MongoIterable<String> collectionNames = database.listCollectionNames();
        for(String name : collectionNames)
            if(name.equals(collectionName))
                return true;
        return false;
    }

    public static MongoDatabase getDatabase() {
        return database;
    }

}
