package xpertss.crypto.kms.provider.signature.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import xpertss.crypto.kms.provider.rsa.KmsRSAKeyFactory;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;
import xpertss.crypto.kms.provider.KeyIds;
import xpertss.crypto.kms.provider.signature.KmsSignatureTest;

import java.security.KeyPair;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSASSA_PSS_SHA512_Test extends KmsSignatureTest {

    @BeforeAll
    public static void initProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected KeyPair getKeyPair() throws Exception {
        return KmsRSAKeyFactory.getKeyPair(kmsClient, KeyIds.SIGN_RSA);
    }

    @Override
    protected KmsSigningAlgorithm getKmsSigningAlgorithm() {
        return KmsSigningAlgorithm.RSASSA_PSS_SHA_512;
    }

    @Override
    protected String getSigningAlgorithm() {
        return "RSASSA-PSS";
    }

    @Override
    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    }
}
