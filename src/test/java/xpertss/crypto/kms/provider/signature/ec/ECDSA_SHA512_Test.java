package xpertss.crypto.kms.provider.signature.ec;

import xpertss.crypto.kms.provider.ec.KmsECKeyFactory;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;
import xpertss.crypto.kms.provider.KeyIds;
import xpertss.crypto.kms.provider.signature.KmsSignatureTest;

import java.security.KeyPair;

public class ECDSA_SHA512_Test extends KmsSignatureTest {

    @Override
    protected KeyPair getKeyPair() throws Exception {
        return KmsECKeyFactory.getKeyPair(kmsClient, KeyIds.SIGN_ECC_NIST_521);
    }

    @Override
    protected KmsSigningAlgorithm getKmsSigningAlgorithm() {
        return KmsSigningAlgorithm.ECDSA_SHA_512;
    }

}
