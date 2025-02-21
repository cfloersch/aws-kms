package xpertss.crypto.kms.provider.rsa;

import xpertss.crypto.kms.provider.KmsPublicKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class KmsRSAPublicKey implements KmsPublicKey, RSAPublicKey {

    private final String id;
    private final RSAPublicKey publicKey;

    KmsRSAPublicKey(String id, RSAPublicKey publicKey)
    {
        this.id = Objects.requireNonNull(id, "id");
        this.publicKey = publicKey;
    }

    public String getId()
    {
        return id;
    }

    public RSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public BigInteger getPublicExponent() {
        return publicKey.getPublicExponent();
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
    public BigInteger getModulus() {
        return publicKey.getModulus();
    }

}
