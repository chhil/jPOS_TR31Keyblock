package org.jpos.security.jceadapter;

import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.keyblock.tr31.Algorithm;
import org.keyblock.tr31.Export;
import org.keyblock.tr31.Header;
import org.keyblock.tr31.KeyblockType;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
// ... other necessary imports from your library

public class TR31HeaderMapper {

    /**
     * Creates a TR-31 Header from jPOS key attributes.
     *
     * @param keyType
     *         The jPOS key type string (e.g., ZMK, ZPK, TMK).
     * @param keyLength
     *         The key length in bits.
     * @return A configured TR-31 Header object.
     * @throws SMException
     *         if the key type is unsupported.
     */
    public static Header fromJposKeyType(String keyType, short keyLength) throws SMException {
        Header header = new Header();
        //        header.setVersion(Version.B_PAYSHIELD_TDEA_DERIVATION); // A common default
        header.setKeyBlockType(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING);
        header.setExport(Export.E_EXPORTABLE_UNDER_TRUSTED_KEY); // Default to exportable

        // Map Algorithm based on key length
        switch (keyLength) {
            //            case SMAdapter.LENGTH_DES:
            case SMAdapter.LENGTH_DES3_2KEY:
            case SMAdapter.LENGTH_DES3_3KEY:
                header.setAlgorithm(Algorithm._T_TRIPLE_DES);
                break;
            // Add case for AES if supported by JCESecurityModule in the future
            default:
                throw new SMException("Unsupported key length for TR-31: " + keyLength);
        }

        // Map Key Usage based on major type
        String majorType = getMajorType(keyType); // Assumes getMajorType is accessible or moved here
        switch (majorType) {
            case SMAdapter.TYPE_ZMK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._K0_KEY_ENCRYPTION_OR_WRAPPING);
                break;
            case SMAdapter.TYPE_TMK:
            case SMAdapter.TYPE_TPK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._K1_TR31_KEY_BLOCK_PROTECTION_KEY);
                break;
            case SMAdapter.TYPE_ZPK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._P0_PIN_ENCRYPTION);
                break;
            case SMAdapter.TYPE_PVK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._V0_PIN_VERIFICATION_KPV_OTHER_ALGORITHM);
                break;
            case SMAdapter.TYPE_TAK:
            case SMAdapter.TYPE_ZAK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._M0_ISO_16609_MAC_ALGORITHM_1_USING_TDEA);
                break;
            case SMAdapter.TYPE_CVK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._C0_CVK_CARD_VERIFICATION_KEY);
                break;
            case SMAdapter.TYPE_BDK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._B0_BDK_BASE_DERIVATION_KEY); // BDK is a type of KEK

                break;
            case SMAdapter.TYPE_DEK:
            case SMAdapter.TYPE_ZEK:
                header.setKeyUsage(org.keyblock.tr31.KeyUsage._D0_DATA_ENCRYPTION);
                break;
            default:
                throw new SMException("Unsupported jPOS key type for TR-31 mapping: " + majorType);
        }

        // The TR31KeyBlock library calculates the length itself, so we don't set it here.
        // Optional Blocks can be added here if needed.

        return header;
    }

    // You might need to make getMajorType public or move its logic here
    private static String getMajorType(String keyType) {
        Matcher m = KEY_TYPE_PATTERN.matcher(keyType); // Assumes KEY_TYPE_PATTERN is accessible
        m.find();
        if (m.group(1) != null)
            return m.group(1);
        throw new IllegalArgumentException("Missing key type");
    }

    // You will need to make KEY_TYPE_PATTERN public in JCESecurityModule or move it here.
    private static final Pattern KEY_TYPE_PATTERN = Pattern.compile("([^:;]*)([:;])?([^:;])?([^:;])?");
}