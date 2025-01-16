package xpertss.crypto.kms.provider.signature.rsa;

import xpertss.crypto.kms.provider.rsa.KmsRSAKeyFactory;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;
import xpertss.crypto.kms.provider.KeyIds;
import xpertss.crypto.kms.provider.signature.KmsSignatureTest;

import java.security.KeyPair;

public class RSASSA_PKCS1_V1_5_SHA384_Test extends KmsSignatureTest {
    
    @Override
    protected KeyPair getKeyPair() throws Exception {
        return KmsRSAKeyFactory.getKeyPair(kmsClient, KeyIds.SIGN_RSA);
    }

    @Override
    protected KmsSigningAlgorithm getKmsSigningAlgorithm() {
        return KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_384;
    }

}
