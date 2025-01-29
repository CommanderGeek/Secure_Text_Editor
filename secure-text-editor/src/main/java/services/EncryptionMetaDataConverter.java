package services;

import DTOs.EncryptionMetadata;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

public class EncryptionMetaDataConverter {

    final Path baseDir = Paths.get(System.getProperty("user.home"), "STE", "encryption", "MetaData");

    private static final Logger logger = LoggerFactory.getLogger(EncryptionMetaDataConverter.class);
    public EncryptionMetadata lookUpMetaData(String id){
        String json = getMetaDataFromSystem(id);
        if(json == ""){
            return null;
        }
        return deserializeMetadata(json);
    }

    private String getMetaDataFromSystem(String uiid)  {
        String fileName = System.getProperty("user.home");
        fileName+= "\\STE\\encryption\\MetaData\\"+uiid.toString()+".json";
        Path path = Paths.get(fileName);
        try {
            return Files.readString(path);
        } catch (IOException e) {
            System.out.println("File does not exist!");
            e.printStackTrace();
        }
        return "";
    }

    public void storeMetaData(String json, UUID uuid) {

        createDirectories(baseDir);

        Path filePath = baseDir.resolve(uuid.toString() + ".json");

        try {
            Files.write(filePath, json.getBytes());
        } catch (IOException e) {
            logger.error("File could not be stored!", e);
        }
    }

    public void createDirectories(Path directory) {
        try {
            if (Files.notExists(directory)) {
                Files.createDirectories(directory);
            }
        } catch (IOException e) {
            logger.error("Directory creation failed for path: " + directory, e);
        }
    }

    public String serializeMetadata(EncryptionMetadata metadata) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(metadata);  // Convert the metadata object to a JSON string
    }
    public EncryptionMetadata deserializeMetadata(String jsonMetadata) {
        Gson gson = new Gson();
        return gson.fromJson(jsonMetadata, EncryptionMetadata.class);
    }
}
