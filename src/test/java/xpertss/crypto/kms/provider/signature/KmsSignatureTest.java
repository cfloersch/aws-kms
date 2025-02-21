package xpertss.crypto.kms.provider.signature;

import xpertss.crypto.kms.provider.KmsKey;
import xpertss.crypto.kms.provider.KmsProvider;
import xpertss.crypto.kms.provider.KmsPublicKey;
import xpertss.crypto.kms.provider.util.StringUtil;
import software.amazon.awssdk.services.kms.KmsClient;

import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class KmsSignatureTest {

    protected final KmsClient kmsClient;
    protected final KmsProvider kmsProvider;

    public KmsSignatureTest() {
        this.kmsClient = KmsClient.builder().build();
        this.kmsProvider = new KmsProvider(kmsClient);
    }

    protected abstract KeyPair getKeyPair() throws Exception;

    protected abstract KmsSigningAlgorithm getKmsSigningAlgorithm();

    protected String getSigningAlgorithm() {
        return getKmsSigningAlgorithm().getAlgorithm();
    }

    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return null;
    }

    @Test
    public void test()
        throws Exception
    {
        KeyPair keyPair = getKeyPair();
        KmsSigningAlgorithm kmsSigningAlgorithm = getKmsSigningAlgorithm();

        String keyId = ((KmsKey) keyPair.getPrivate()).getId();

        System.out.println();
        System.out.println("----------------------------------------------");
        System.out.printf("Testing Key [ %s ] with Algorithm [ %s ]%n", keyId, kmsSigningAlgorithm.name());
        System.out.println("----------------------------------------------");

        String message = "text to be signed!";

        Signature kmsSignature = Signature.getInstance(kmsSigningAlgorithm.getAlgorithm(), kmsProvider);
        kmsSignature.initSign(keyPair.getPrivate());
        kmsSignature.update(message.getBytes());
        byte[] signatureBytes = kmsSignature.sign();

        System.out.println(String.format("Signature: %s", StringUtil.hex(signatureBytes)));

        kmsSignature.initVerify(keyPair.getPublic());
        kmsSignature.update(message.getBytes());
        boolean valid = kmsSignature.verify(signatureBytes);

        System.out.println(String.format("Verification via KMS: %s", valid));
        assertTrue(valid, "Verification via KMS failed!");

        Signature defaultSignature = Signature.getInstance(getSigningAlgorithm());
        AlgorithmParameterSpec algorithmParameterSpec = getAlgorithmParameterSpec();
        if (algorithmParameterSpec != null) {
            defaultSignature.setParameter(algorithmParameterSpec);
        }
        defaultSignature.initVerify(((KmsPublicKey) keyPair.getPublic()).getPublicKey());
        defaultSignature.update(message.getBytes());
        valid = defaultSignature.verify(signatureBytes);

        System.out.println(String.format("Verification via Default Provider: %s", valid));
        assertTrue(valid, "Verification via Default Provider failed!");
    }

}
