package xpertss.crypto.kms.provider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class KmsKeyStoreTest {

    @BeforeAll
    public static void initProvider() {
        Security.addProvider(new KmsProvider());
    }

    //protected final KmsClient kmsClient;
    protected final KmsProvider kmsProvider;

    public KmsKeyStoreTest() {
        //this.kmsClient = KmsClient.builder().build();
        this.kmsProvider = new KmsProvider();
    }

    @Test
    public void testAliases()
        throws GeneralSecurityException, IOException
    {
        //KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        KeyStore keyStore = KeyStore.getInstance("KMS");
        keyStore.load(null, null);

        Enumeration<String> aliases = keyStore.aliases();
        assertTrue(aliases.hasMoreElements());
    }

    @Test
    public void testContainsAlias()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS");
        keyStore.load(null, null);

        boolean contains = keyStore.containsAlias(KeyIds.SIGN_RSA_4096_ALIAS);
        assertTrue(contains);
    }

    @Test
    public void testNotContainsAlias()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        keyStore.load(null, null);

        boolean contains = keyStore.containsAlias(UUID.randomUUID().toString());
        assertFalse(contains);
    }

    @Test
    public void testSize()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        keyStore.load(null, null);

        int size = keyStore.size();
        assertTrue(size > 0);
    }

    @Test
    public void testGetRsaKey()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        keyStore.load(null, null);

        Key key = keyStore.getKey(KeyIds.SIGN_RSA_4096_ALIAS, null);
        assertNotNull(key);
        assertInstanceOf(KmsKey.class, key);
        assertInstanceOf(RSAPrivateKey.class, key);
    }

    @Test
    public void testGetEcKey()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        keyStore.load(null, null);

        Key key = keyStore.getKey(KeyIds.SIGN_ECC_NIST_521_ALIAS, null);
        assertNotNull(key);
        assertInstanceOf(KmsKey.class, key);
        assertInstanceOf(ECPrivateKey.class, key);
    }

    @Test
    public void testGetEncryptKey()
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("KMS", this.kmsProvider);
        keyStore.load(null, null);

        try {
            keyStore.getKey(KeyIds.RSA_ENCRYPT_ALIAS, null);
            fail();
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().startsWith("Unsupported Key type"));
        } catch (Exception e) {
            fail();
        }
    }

}
