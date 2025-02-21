package xpertss.crypto.kms.provider.ec;

import xpertss.crypto.kms.provider.KmsKey;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Objects;

public class KmsECPrivateKey implements KmsKey, ECPrivateKey {

    private final String id;
    private final String algorithm = "EC";
    private final String format = "PKCS#8";

    KmsECPrivateKey(String id)
    {
        this.id = Objects.requireNonNull(id, "id");
    }

    public String getId()
    {
        return id;
    }


    @Override
    public String getAlgorithm()
    {
        return algorithm;
    }

    @Override
    public String getFormat()
    {
        return format;
    }


    @Override
    public BigInteger getS() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ECParameterSpec getParams() {
        throw new UnsupportedOperationException();
    }

}
