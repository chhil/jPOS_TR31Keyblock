package org.jpos.security.jceadapter;


import org.jpos.iso.ISOUtil;
import org.jpos.security.SecureDESKey;
import org.jpos.security.SMException;
import java.security.Key;

/**
 * Provides interoperability between the legacy JCESecurityModule (using LMK variants)
 * and the modern JSecurityModuleTR31 (using TR-31 key blocks).
 *
 * This class orchestrates the conversion of a SecureDESKey from one format to the other
 * by decrypting it to its clear form using the source module and re-encrypting it
 * with the destination module.
 */
public class KeyConverter {

    private final JCESecurityModule variantModule;
    private final JSecurityModuleTR31 tr31Module;

    /**
     * Constructs a KeyConverter.
     *
     * @param variantModule An initialized instance of JCESecurityModule for handling variant-based keys.
     * @param tr31Module    An initialized instance of JSecurityModuleTR31 for handling TR-31 key blocks.
     */
    public KeyConverter(JCESecurityModule variantModule, JSecurityModuleTR31 tr31Module) {
        this.variantModule = variantModule;
        this.tr31Module = tr31Module;
    }

    /**
     * Converts a key encrypted under the legacy LMK variant scheme to a TR-31 key block.
     *
     * @param variantKey The source SecureDESKey encrypted using the LMK variant scheme.
     * @return A new SecureDESKey containing the key as a TR-31 key block.
     * @throws SMException if the conversion fails.
     */
    public SecureDESKey convertVariantToTR31(SecureDESKey variantKey) throws SMException {
        if (variantKey == null) {
            throw new SMException("Source variant key cannot be null.");
        }

        System.out.println("--- Converting Variant Key to TR-31 Key Block ---");
        System.out.println("1. Decrypting source variant key to get the clear key...");
        // Step 1: Get the clear key using the legacy module
        Key clearKey = variantModule.decryptFromLMK(variantKey);
        System.out.println("   > Clear key obtained successfully.");

        System.out.println("2. Re-encrypting the clear key into a TR-31 Key Block...");
        // Step 2: Re-encrypt the clear key using the TR-31 module
        SecureDESKey tr31Key = tr31Module.encryptToLMK(
                variantKey.getKeyLength(),
                variantKey.getKeyType(),
                clearKey
        );
        System.out.println("   > TR-31 Key Block created successfully.");
        System.out.println("--- Conversion Complete ---");
        return tr31Key;
    }

    /**
     * Converts a key stored as a TR-31 key block to the legacy LMK variant encryption scheme.
     *
     * @param tr31Key The source SecureDESKey containing the key as a TR-31 key block.
     * @return A new SecureDESKey encrypted using the legacy LMK variant scheme.
     * @throws SMException if the conversion fails.
     */
    public SecureDESKey convertTR31ToVariant(SecureDESKey tr31Key) throws SMException {
        if (tr31Key == null) {
            throw new SMException("Source TR-31 key cannot be null.");
        }

        System.out.println("--- Converting TR-31 Key Block to Variant Key ---");
        System.out.println("1. Decrypting source TR-31 key block to get the clear key...");
        // Step 1: Get the clear key using the TR-31 module
        Key clearKey = tr31Module.decryptFromLMK(tr31Key);
        System.out.println("   > Clear key obtained successfully.");

        System.out.println("2. Re-encrypting the clear key using the legacy variant scheme...");
        // Step 2: Re-encrypt the clear key using the legacy module
        SecureDESKey variantKey = variantModule.encryptToLMK(
                tr31Key.getKeyLength(),
                tr31Key.getKeyType(),
                clearKey
        );
        System.out.println("   > Legacy variant key created successfully.");
        System.out.println("--- Conversion Complete ---");
        return variantKey;
    }
}