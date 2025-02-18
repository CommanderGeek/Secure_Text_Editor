package services;

import DTOs.EncryptionMetadata;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * @author Elias Harb
 * @version 1.0
 * The {@code EncryptionMetaDataConverter} class is responsible for handling encryption metadata storage and retrieval.
 * <p>
 * This includes:
 * <ul>
 *   <li>Looking up stored encryption metadata by UUID.</li>
 *   <li>Serializing and deserializing metadata to/from JSON.</li>
 *   <li>Creating and managing metadata storage directories.</li>
 *   <li>Writing metadata to the filesystem.</li>
 * </ul>
 *
 * <p><b>Example Usage:</b></p>
 * <pre>
 *     EncryptionMetaDataConverter converter = new EncryptionMetaDataConverter();
 *     EncryptionMetadata metadata = converter.lookUpMetaData("some-uuid");
 *     String json = converter.serializeMetadata(metadata);
 *     converter.storeMetaData(json, UUID.randomUUID());
 * </pre>
 *
 */
public class EncryptionMetaDataConverter {
    /**
     * Base directory where encryption metadata is stored.
     */
    final Path baseDir = Paths.get(System.getProperty("user.home"), "STE", "encryption", "MetaData");

    private static final Logger logger = LoggerFactory.getLogger(EncryptionMetaDataConverter.class);

    /**
     * Retrieves encryption metadata by looking up the given ID.
     *
     * @param id The unique identifier (UUID) for the metadata file.
     * @return The {@link EncryptionMetadata} object if found, otherwise {@code null}.
     */
    public EncryptionMetadata lookUpMetaData(String id){
        String json = getMetaDataFromSystem(id);
        if(json.isEmpty()){
            return null;
        }
        return deserializeMetadata(json);
    }

    /**
     * Reads metadata from the filesystem based on a UUID.
     *
     * @param uuid The unique identifier for the metadata file.
     * @return A JSON string containing the metadata, or an empty string if the file is not found.
     */
    private String getMetaDataFromSystem(String uuid)  {
        String fileName = System.getProperty("user.home");
        fileName+= "\\STE\\encryption\\MetaData\\"+ uuid +".json";
        Path path = Paths.get(fileName);
        try {
            return Files.readString(path);
        } catch (IOException e) {
            System.out.println("File does not exist!");
            e.printStackTrace();
        }
        return "";
    }

    /**
     * Stores encryption metadata as a JSON file.
     * <p>
     * This method ensures that the necessary directories exist before writing the file.
     *
     * @param json The metadata JSON string to store.
     * @param uuid The unique identifier for the metadata file.
     */
    public void storeMetaData(String json, UUID uuid) {

        createDirectories(baseDir);

        Path filePath = baseDir.resolve(uuid.toString() + ".json");
        // Write the JSON metadata to the file with Files
        try {
            Files.write(filePath, json.getBytes());
        } catch (IOException e) {
            logger.error("File could not be stored!", e);
        }
    }

    /**
     * Creates the necessary directories if they do not already exist.
     *
     * @param directory The directory path to create.
     */
    public void createDirectories(Path directory) {
        try {
            if (Files.notExists(directory)) {
                Files.createDirectories(directory);
            }
        } catch (IOException e) {
            logger.error("Directory creation failed for path: " + directory, e);
        }
    }
    /**
     * Serializes an {@link EncryptionMetadata} object into a JSON string.
     *
     * @param metadata The metadata object to serialize.
     * @return A JSON string representation of the metadata.
     */
    public String serializeMetadata(EncryptionMetadata metadata) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(metadata);  // Convert the metadata object to a JSON string
    }

    /**
     * Deserializes a JSON string into an {@link EncryptionMetadata} object.
     *
     * @param jsonMetadata The JSON string containing the metadata.
     * @return The deserialized {@link EncryptionMetadata} object.
     */

    public EncryptionMetadata deserializeMetadata(String jsonMetadata) {
        Gson gson = new Gson();
        return gson.fromJson(jsonMetadata, EncryptionMetadata.class);
    }
}
