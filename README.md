/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.crisil.trino.udf;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import io.airlift.slice.Slice;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlType;
import io.trino.spi.type.StandardTypes;
import jdk.jfr.Description;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.airlift.slice.Slices.utf8Slice;

/**
 * Secure Hashing with HMAC-SHA256 using Azure Key Vault
 */
public final class EncryptPCIData
{
    /**
     * ALGORITHM FOR HASH GENERATION.
     */
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    /**
     * AZURE KEY VAULT URL.
     */
    private static final String KEY_VAULT_URL = "https://your-keyvault-name.vault.azure.net/";
    /**
     * AKV Secret Name.
     */
    private static final String SECRET_NAME = "lakehouse-encryption-key";
    /**
     * Initializing Cached Key.
     */
    // Global cache for the key with expiration time
    private static byte[] cachedKey;
    /**
     * Cache Expiry.
     */
    private static long cacheExpiry;
    /**
     * Cached Key TTL
     */
    private static final long KEY_CACHE_TTL = 3600 * 1000; // 1 hour in milliseconds

    private EncryptPCIData()
    {
        throw new UnsupportedOperationException("This is a utility class and" + " cannot be instantiated");
    }

    /**
     * Function to fetch the key without caching.
     */
  /*  private static SecretKeySpec fetchKeyFromKeyVault()
    {
        // Authenticate using Managed Identity or Service Principal
        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl(KEY_VAULT_URL)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        // Retrieve the secret (HMAC key) from Azure Key Vault
        String keyBase64 = secretClient.getSecret(SECRET_NAME).getValue();
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        return new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }*/
    /**
     * Fetching key from AKV with caching approach.
     */
    private static byte[] getKeyFromAzure()
    {
        long currentTime = System.currentTimeMillis();

        // If we have a cached key that hasn't expired, use it
        if (cachedKey != null && currentTime < cacheExpiry) {
            return cachedKey;
        }

        try {
            // Hardcoded Azure Key Vault details
            String vaultUrl = "";
            String secretName = "";

          
            // Create a ClientSecretCredential with hardcoded values
            ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                    .tenantId(tenantId)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();

            // Create SecretClient with the credential
            SecretClient secretClient = new SecretClientBuilder()
                    .vaultUrl(vaultUrl)
                    .credential(credential)
                    .buildClient();

            // Retrieve the secret from Azure Key Vault
            KeyVaultSecret retrievedSecret = secretClient.getSecret(secretName);

            // Update the cache with the new key and expiry time
            cachedKey = Base64.getDecoder().decode(retrievedSecret.getValue());
            cacheExpiry = currentTime + KEY_CACHE_TTL;

            return cachedKey;
        }
        catch (Exception e) {
            // If fetching fails, but we have an expired key, use it as fallback
            if (cachedKey != null) {
                return cachedKey;
            }
            throw new RuntimeException("Failed to retrieve key from Azure Key Vault: " + e.getMessage(), e);
        }
    }

    /**
     * UDF for hash based encryption.
     */
    @Description("Hash-based UDF for PCI-DSS data")
    @ScalarFunction("encrypt_pci_udf")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice hash(@SqlType(StandardTypes.VARCHAR) Slice input)
            throws Exception
    {
        try {
            byte[] key = getKeyFromAzure();
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            mac.init(secretKey);
            byte[] hashBytes = mac.doFinal(input.toStringUtf8().getBytes(StandardCharsets.UTF_8));
            return utf8Slice(Base64.getEncoder().encodeToString(hashBytes));
        }
        catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    public static void main(String[] args)
            throws Exception
    {
        String input = "Hello, Trino!";
        Slice hash1 = hash(utf8Slice(input));
        Slice hash2 = hash(utf8Slice(input));

        System.out.println("Hash 1: " + hash1.toStringUtf8());
        System.out.println("Hash 2: " + hash2.toStringUtf8());
        System.out.println("Deterministic: " + hash1.toStringUtf8().equals(hash2.toStringUtf8())); // Should be true
    }
}

