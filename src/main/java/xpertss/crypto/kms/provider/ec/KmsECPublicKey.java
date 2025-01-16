package xpertss.crypto.kms.provider.ec;

import xpertss.crypto.kms.provider.KmsPublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Objects;

public class KmsECPublicKey implements KmsPublicKey, ECPublicKey {

    private final String id;
    private final ECPublicKey publicKey;

    KmsECPublicKey(String id, ECPublicKey publicKey)
    {
        this.id = Objects.requireNonNull(id, "id");
        this.publicKey = publicKey;
    }

    public String getId()
    {
        return id;
    }

    public ECPublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public ECPoint getW() {
        return publicKey.getW();
    }

    @Override
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return publicKey.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return publicKey.getEncoded();
    }

    @Override
    public ECParameterSpec getParams() {
        return publicKey.getParams();
    }

}
