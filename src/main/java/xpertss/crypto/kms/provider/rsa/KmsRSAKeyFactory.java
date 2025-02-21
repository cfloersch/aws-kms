package xpertss.crypto.kms.provider.rsa;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public abstract class KmsRSAKeyFactory {

    /**
     * Retrieve KMS KeyPair reference (Private Key / Public Key) based on the keyId informed.
     * Also fetch the real Public Key from KMS.
     * Use only when it is necessary the real Public Key.
     *
     * @param kmsClient
     * @param keyId
     * @return
     */
    public static KeyPair getKeyPair(KmsClient kmsClient, String keyId)
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        Objects.requireNonNull(kmsClient, "kmsClient");
        Objects.requireNonNull(keyId, "keyId");
        return new KeyPair(getPublicKey(kmsClient, keyId), getPrivateKey(keyId));
    }

    /**
     * Retrieve KMS KeyPair reference (Private Key / Public Key) based on the keyId informed.
     * The real Public Key is not fetched.
     *
     * @param keyId
     * @return
     */
    public static KeyPair getKeyPair(String keyId) {
        Objects.requireNonNull(keyId, "keyId");
        return new KeyPair(getPublicKey(keyId), getPrivateKey(keyId));
    }

    /**
     * Retrieve KMS Private Key reference based on the keyId informed.
     *
     * @param keyId
     * @return
     */
    public static KmsRSAPrivateKey getPrivateKey(String keyId) {
        Objects.requireNonNull(keyId, "keyId");
        return new KmsRSAPrivateKey(keyId);
    }

    /**
     * Retrieve KMS Public Key reference based on the keyId informed.
     *
     * @param keyId
     * @return
     */
    public static KmsRSAPublicKey getPublicKey(String keyId) {
        Objects.requireNonNull(keyId, "keyId");
        return new KmsRSAPublicKey(keyId, null);
    }

    /**
     * Retrieve KMS Public Key reference based on the keyId informed.
     * Also fetch the real Public Key from KMS.
     * Use only when it is necessary the real Public Key.
     *
     * @param kmsClient
     * @param keyId
     * @return
     */
    public static KmsRSAPublicKey getPublicKey(KmsClient kmsClient, String keyId)
        throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        Objects.requireNonNull(kmsClient, "kmsClient");
        Objects.requireNonNull(keyId, "keyId");
        GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(getPublicKeyResponse.publicKey().asByteArray());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return new KmsRSAPublicKey(keyId, (RSAPublicKey) keyFactory.generatePublic(keySpec));
    }

}
