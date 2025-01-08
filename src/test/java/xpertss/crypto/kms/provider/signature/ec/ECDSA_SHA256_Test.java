package xpertss.crypto.kms.provider.signature.ec;

import xpertss.crypto.kms.provider.ec.KmsECKeyFactory;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;
import xpertss.crypto.kms.provider.KeyIds;
import xpertss.crypto.kms.provider.signature.KmsSignatureTest;

import java.security.KeyPair;

public class ECDSA_SHA256_Test extends KmsSignatureTest {

    @Override
    protected KeyPair getKeyPair() {
        return KmsECKeyFactory.getKeyPair(kmsClient, KeyIds.SIGN_ECC_NIST_256);
    }

    @Override
    protected KmsSigningAlgorithm getKmsSigningAlgorithm() {
        return KmsSigningAlgorithm.ECDSA_SHA_256;
    }

}
