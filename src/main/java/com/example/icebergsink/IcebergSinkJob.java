package com.example.icebergsink;
import org.apache.flink.table.api.*;

public class IcebergSinkJob {
    public static void main(String[] args) {
        // Initialize the Flink TableEnvironment
        EnvironmentSettings settings = EnvironmentSettings.newInstance().inStreamingMode().build();
        TableEnvironment tableEnv = TableEnvironment.create(settings);

        // Define the Iceberg JDBC Catalog
        tableEnv.executeSql(
       ""
        );

        // Switch to the Iceberg catalog
        tableEnv.executeSql("USE CATALOG iceberg_jdbc3");

        // Create a table in the Iceberg catalog
        tableEnv.executeSql(
            "CREATE TABLE TEST_APPLE (" +
            "  column1 BIGINT" +
            ") WITH (" +
            "'write.format.default' = 'parquet'" +
            ")"
        );

        // Insert data into the table
        tableEnv.executeSql("INSERT INTO TEST_APPLE VALUES (11134)");
        tableEnv.executeSql("Select * from TEST_APPLE");
    }
}
