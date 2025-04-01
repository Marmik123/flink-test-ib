Caused by: java.security.InvalidAlgorithmParameterException: Unsupported parameter: javax.crypto.spec.GCMParameterSpec@329503b6/*
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

import io.airlift.slice.Slice;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlType;
import io.trino.spi.type.StandardTypes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static io.airlift.slice.Slices.utf8Slice;

public final class EncryptDecryptUDF
{
    /**
     * ALGORITHM.
     */
    private static final String ALGORITHM = "AES";
    /**
     * GCM TAG in bits.
     */
    private static final int GCM_TAG_LENGTH = 128; // Bits
    /**
     * AES key fetched from secure vault.
     */
    // Fetch AES Key from Azure Key Vault (Use singleton to avoid multiple API calls)
    private static final SecretKey AES_KEY = getKeyFromVault();

    private EncryptDecryptUDF()
    {
        throw new UnsupportedOperationException("This is a utility class and" + " cannot be instantiated");
    }

    /**
     * Function to fetch the key.
     */
    private static SecretKey getKeyFromVault()
    {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGenerator.init(192);
        SecretKey key = keyGenerator.generateKey();
        return key;
   /*     SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl("https://hbl-az-lh-preprod-akv.vault.azure.net")
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();*/

//        KeyVaultSecret retrievedSecret = secretClient.getSecret("encrpass");
//        byte[] decodedKey = Base64.getDecoder().decode(retrievedSecret.getValue());
//        return new SecretKeySpec(decodedKey, "AES");
    }

    @Description("Encrypt data using AES-GCM")
    @ScalarFunction("encrypt_udf")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt(final @SqlType(StandardTypes.VARCHAR) Slice plaintext)
    {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[12]; // 96-bit IV for AES-GCM
            new java.security.SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, AES_KEY, gcmSpec);

            byte[] encrypted = cipher.doFinal(plaintext.toStringUtf8().getBytes(StandardCharsets.UTF_8));
            return utf8Slice(Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted));
        }
        catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    @Description("Decrypt data using AES-GCM")
    @ScalarFunction("decrypt_udf")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decrypt(final @SqlType(StandardTypes.VARCHAR) Slice encryptedText)
    {
        try {
            String[] parts = encryptedText.toStringUtf8().split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedData = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, AES_KEY, gcmSpec);

            byte[] decrypted = cipher.doFinal(encryptedData);
            return utf8Slice(decrypted.toString());
        }
        catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }
}

