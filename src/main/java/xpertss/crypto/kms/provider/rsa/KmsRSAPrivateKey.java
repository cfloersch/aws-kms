package xpertss.crypto.kms.provider.rsa;

import xpertss.crypto.kms.provider.KmsKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

public class KmsRSAPrivateKey implements KmsKey, RSAPrivateKey {

    private final String id;
    private final String algorithm = "RSA";
    private final String format = "X.509";

    KmsRSAPrivateKey(String id)
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
    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }

    @Override
    public BigInteger getModulus() {
        throw new UnsupportedOperationException();
    }

}
