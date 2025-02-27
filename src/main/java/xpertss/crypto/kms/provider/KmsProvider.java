package xpertss.crypto.kms.provider;

import xpertss.crypto.kms.provider.signature.KmsSignature;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;
import software.amazon.awssdk.services.kms.KmsClient;

import java.security.Provider;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

public class KmsProvider extends Provider {
    public KmsProvider() {
        this(KmsClient.builder().build());
    }

    public KmsProvider(KmsClient kmsClient) {
        super("KMS", 1.0, "AWS KMS Provider");
        registerSignatures(Objects.requireNonNull(kmsClient, "kmsClient"));
    }

    private void registerSignatures(final KmsClient kmsClient) {
        this.putService(new KmsKeyStoreService(this, kmsClient));
        Stream.of(KmsSigningAlgorithm.values()).forEach(s -> this.putService(new KmsSignatureProviderService(this, kmsClient, s)));
    }

    private static class KmsKeyStoreService extends Service {

        private final KmsClient kmsClient;

        public KmsKeyStoreService(Provider provider, KmsClient kmsClient) {
            super(provider, "KeyStore", "KMS", KmsKeyStore.class.getName(), Collections.emptyList(), Collections.emptyMap());
            this.kmsClient = kmsClient;
        }

        public Object newInstance(Object constructorParameter) {
            return new KmsKeyStore(kmsClient);
        }
    }

    private static class KmsSignatureProviderService extends Service {

        private final KmsClient kmsClient;
        private final KmsSigningAlgorithm kmsSigningAlgorithm;

        public KmsSignatureProviderService(Provider provider, KmsClient kmsClient, KmsSigningAlgorithm kmsSigningAlgorithm) {
            super(provider, "Signature", kmsSigningAlgorithm.getAlgorithm(), KmsSignature.class.getName(), Collections.emptyList(), Collections.emptyMap());
            this.kmsClient = kmsClient;
            this.kmsSigningAlgorithm = kmsSigningAlgorithm;
        }

        public Object newInstance(Object constructorParameter) {
            return new KmsSignature(kmsClient, kmsSigningAlgorithm);
        }
    }

}
