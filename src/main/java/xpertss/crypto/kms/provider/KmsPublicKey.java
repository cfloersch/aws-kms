package xpertss.crypto.kms.provider;

import java.security.PublicKey;

public interface KmsPublicKey extends KmsKey {

    PublicKey getPublicKey();

}
