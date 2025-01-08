package xpertss.crypto.kms.provider;

/**
 * Before test in your environment update the Ids reference.
 */
public interface KeyIds {

    // ECC Key (4096 size) defined for sign/verify
    String SIGN_RSA_4096_ALIAS = "RSA4096";
    String SIGN_RSA = "20a2af5d-f5e0-4063-a7cd-c06853311513";


    // ECC Key (256 size) defined for sign/verify
    String SIGN_ECC_NIST_256 = "397b1542-7e8a-4efa-8aa7-e132361e4fe6";

    // ECC Key (384 size) defined for sign/verify
    String SIGN_ECC_NIST_384 = "ddabe72a-6e45-41b5-a67f-21f62bf9d82a";

    // ECC Key (521 size) defined for sign/verify
    String SIGN_ECC_NIST_521_ALIAS = "EC521";
    String SIGN_ECC_NIST_521 = "21252638-c2a0-4870-b3ea-8f427d2356c5";

    // RSA Key (Any size) defined for encrypt/decrypt rather than sign/verify
    String RSA_ENCRYPT_ALIAS = "RSAEncrypt";
    String RSA_ENCRYPT = "54f3844d-99ec-48c2-ae8f-2209d3531f2b";

}
