package org.jpos.security.jceadapter;


import at.favre.lib.bytes.Bytes;
import org.jpos.core.SimpleConfiguration;
import org.jpos.util.Logger;
import org.jpos.util.SimpleLogListener;
import org.keyblock.tr31.*;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SecureDESKey;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.Util;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * An extension of JCESecurityModule that uses TR-31 key blocks for key storage
 * instead of the proprietary LMK variant scheme.
 * <p>
 * This module requires two special LMKs to be configured:
 * <ul>
 *   <li><b>LMK 0x0E:</b> A TDES key to be used as the Key Block Protection Key (KBPK) for TDES keys.</li>
 *   <li><b>LMK 0x0F:</b> An AES key to be used as the Key Block Protection Key (KBPK) for AES keys.</li>
 * </ul>
 * All keys managed by this module are wrapped in TR-31 format using one of these KBPKs.
 */
public class JSecurityModuleTR31 extends JCESecurityModule {

    private static final int TDES_KBPK_INDEX = 0x10;
    private static final int AES_KBPK_INDEX  = 0x11;


    private static final Map<String, KeyUsage> jposTypeToTr31Usage = new HashMap<>();

    static {
        // Map jPOS key types to their standard TR-31 usage attributes
        jposTypeToTr31Usage.put(SMAdapter.TYPE_ZMK, KeyUsage._K0_KEY_ENCRYPTION_OR_WRAPPING);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_TMK, KeyUsage._K0_KEY_ENCRYPTION_OR_WRAPPING);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_TPK, KeyUsage._P0_PIN_ENCRYPTION);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_ZPK, KeyUsage._P0_PIN_ENCRYPTION);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_TAK, KeyUsage._M1_ISO_9797_1_MAC_ALGORITHM_1);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_ZAK, KeyUsage._M1_ISO_9797_1_MAC_ALGORITHM_1);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_BDK, KeyUsage._B0_BDK_BASE_DERIVATION_KEY);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_CVK, KeyUsage._C0_CVK_CARD_VERIFICATION_KEY);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_PVK, KeyUsage._V2_PIN_VERIFICATION_VISA_PVV);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_DEK, KeyUsage._D0_DATA_ENCRYPTION);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_ZEK, KeyUsage._D0_DATA_ENCRYPTION);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_MK_AC, KeyUsage._E0_EMV_CHIP_CARD_MASTER_KEY_APPLICATION_CRYPTOGRAMS);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_MK_SMI, KeyUsage._E2__EMV_CHIP_CARD_MASTER_KEY_SECURE_MESSAGING_FOR_INTEGRITY);
        jposTypeToTr31Usage.put(SMAdapter.TYPE_MK_SMC, KeyUsage._E1_EMV_CHIP_CARD_MASTER_KEY_SECURE_MESSAGING_FOR_CONFIDENTIALITY);
    }

    /**
     * Overrides the base implementation to wrap a clear key into a TR-31 key block
     * using the appropriate KBPK (TDES or AES).
     *
     * @param keyLength   The length of the key in bits.
     * @param keyType     The jPOS key type (e.g., ZPK, BDK).
     * @param clearDESKey The clear key to be wrapped.
     * @return A SecureDESKey where the encrypted part is the full TR-31 key block.
     * @throws SMException if the key cannot be wrapped.
     */
    @Override
    protected SecureDESKey encryptToLMK(short keyLength, String keyType, Key clearDESKey) throws SMException {
        try {
            byte[] clearKeyBytes = jceHandler.extractDESKeyMaterial(keyLength, clearDESKey);
            Util.adjustDESParity(clearKeyBytes);

            Header header = new Header();
            header.setVersion("00");
            header.setExport(Export.E_EXPORTABLE_UNDER_TRUSTED_KEY);
            KeyUsage usage = jposTypeToTr31Usage.get(keyType);
            if (usage == null) {
                throw new SMException("No TR-31 key usage mapping for key type: " + keyType);
            }
            header.setKeyUsage(usage);
            header.setKeyUseFor(KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT);

            SecretKey kbpk;
            if (clearDESKey.getAlgorithm().toUpperCase().contains("AES")) {
                header.setKeyBlockType(KeyblockType._D_AES_KEY_DERIVATION);
                header.setAlgorithm(Algorithm._A_AES);
                kbpk = getLMK(AES_KBPK_INDEX);
            } else { // TDES
                header.setKeyBlockType(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING);
                header.setAlgorithm(Algorithm._T_TRIPLE_DES);
                kbpk = getLMK(TDES_KBPK_INDEX);
            }

            TR31KeyBlock keyBlock = new TR31KeyBlock(header);
            keyBlock.setKBPK(ISOUtil.hexString(kbpk.getEncoded()));
            keyBlock.setClearKey(Bytes.from(clearKeyBytes));
            keyBlock.generate();

            byte[] encryptedKeyBlockBytes = keyBlock.toString().getBytes(StandardCharsets.US_ASCII);
            return new SecureDESKey(keyLength, keyType, encryptedKeyBlockBytes, calculateKeyCheckValue(clearDESKey));
        } catch (Exception e) {
            throw new SMException("Failed to create TR-31 key block", e);
        }
    }

    /**
     * Overrides the base implementation to unwrap a TR-31 key block and return
     * the clear key.
     *
     * @param secureDESKey The key to be unwrapped, where getKeyBytes() returns the TR-31 block.
     * @return The clear key.
     * @throws SMException if the key block is invalid or cannot be decrypted.
     */
    @Override
    protected Key decryptFromLMK(SecureDESKey secureDESKey) throws SMException {
        try {
            String keyBlockString = new String(secureDESKey.getKeyBytes(), StandardCharsets.US_ASCII);
            Header header = new Header(keyBlockString);

            SecretKey kbpk;
            String keyAlgorithm;
            if (header.getKeyBlockType().isAES()) {
                kbpk = getLMK(AES_KBPK_INDEX);
                keyAlgorithm = "AES";
            } else { // TDES
                kbpk = getLMK(TDES_KBPK_INDEX);
                keyAlgorithm = "DESede";
            }

            TR31KeyBlock keyBlock = new TR31KeyBlock();
            keyBlock.decryptKeyBlock(keyBlockString, ISOUtil.hexString(kbpk.getEncoded()));

            byte[] clearKeyBytes = keyBlock.getClearKey().array();

            if ("AES".equalsIgnoreCase(keyAlgorithm)) {
                return (Key) jceHandler.formKey(keyAlgorithm, clearKeyBytes);
            } else {
                return jceHandler.formDESKey(secureDESKey.getKeyLength(), clearKeyBytes);
            }
        } catch (Exception e) {
            throw new SMException("Failed to decrypt TR-31 key block", e);
        }
    }

    /**
     * Overrides the base implementation to import a key from a TR-31 block.
     * <p>
     * This method takes a key encrypted under a KEK (both as TR-31 blocks),
     * decrypts the key using the KEK, and then re-encrypts (wraps) the key
     * under the HSM's internal KBPK, returning a new TR-31 block.
     *
     * @param keyLength    The length of the key being imported.
     * @param keyType      The jPOS type of the key being imported (e.g., ZPK).
     * @param encryptedKey The TR-31 block of the key to import (key under KEK).
     * @param kek          The SecureDESKey representing the KEK (itself a TR-31 block under the internal KBPK).
     * @param checkParity  (Not used in this implementation).
     * @return A new SecureDESKey representing the imported key, now wrapped under the internal KBPK.
     * @throws SMException If the import process fails.
     */
    @Override
    public SecureDESKey importKeyImpl(short keyLength, String keyType, byte[] encryptedKey,
            SecureDESKey kek, boolean checkParity) throws SMException {
        try {
            // 1. Get the clear Key Encryption Key (KEK/ZMK)
            Key clearKEK = decryptFromLMK(kek);
            String kekHex = ISOUtil.hexString(jceHandler.extractDESKeyMaterial(kek.getKeyLength(), clearKEK));

            // 2. Decrypt the incoming key block using the clear KEK as the KBPK
            String incomingKeyBlockStr = new String(encryptedKey, StandardCharsets.US_ASCII);
            TR31KeyBlock incomingKeyBlock = new TR31KeyBlock();
            incomingKeyBlock.decryptKeyBlock(incomingKeyBlockStr, kekHex);
            byte[] clearKeyBytes = incomingKeyBlock.getClearKey().array();

            // 3. Form a temporary clear Key object from the decrypted bytes
            Key clearKey;
            Header header = new Header(incomingKeyBlockStr);
            if (header.getAlgorithm().getAlgorithm().contains("AES")) {
                clearKey = jceHandler.formKey("AES", clearKeyBytes);
            } else {
                clearKey = jceHandler.formDESKey(keyLength, clearKeyBytes);
            }

            // 4. Re-encrypt the clear key under the internal LMK/KBPK using the existing encryptToLMK method.
            //    This creates a new TR-31 block for secure storage.
            return encryptToLMK(keyLength, keyType, clearKey);

        } catch (Exception e) {
            throw new SMException("Failed to import key from TR-31 key block", e);
        }
    }

    @Override
    public byte[] exportKeyImpl (SecureDESKey key, SecureDESKey kek) throws SMException {
        try {
            // Get the clear key material of the key to be exported
            Key clearKey = decryptFromLMK(key);
            byte[] clearKeyBytes = jceHandler.extractDESKeyMaterial(key.getKeyLength(), clearKey);

            // Get the clear key material of the Key Encryption Key (KEK/ZMK)
            Key clearKEK = decryptFromLMK(kek);
            byte[] clearKEKBytes = jceHandler.extractDESKeyMaterial(kek.getKeyLength(), clearKEK);

            // Create a new TR-31 header for the exported key block.
            // The attributes are based on the key being exported.
            Header header = new Header();
            header.setVersion("00");
            header.setExport(Export.E_EXPORTABLE_UNDER_TRUSTED_KEY);

            KeyUsage usage = jposTypeToTr31Usage.get(key.getKeyType());
            if (usage == null) {
                throw new SMException("No TR-31 key usage mapping for key type: " + key.getKeyType());
            }
            header.setKeyUsage(usage);
            header.setKeyUseFor(KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT);


            if (key.getKeyLength() > 192) { // Assuming AES
                header.setKeyBlockType(KeyblockType._D_AES_KEY_DERIVATION);
                header.setAlgorithm(Algorithm._A_AES);
            } else { // TDES
                header.setKeyBlockType(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING);
                header.setAlgorithm(Algorithm._T_TRIPLE_DES);
            }

            // Create the key block using the clear KEK as the KBPK
            TR31KeyBlock exportedBlock = new TR31KeyBlock(header);
            exportedBlock.setKBPK(ISOUtil.hexString(clearKEKBytes));
            exportedBlock.setClearKey(Bytes.from(clearKeyBytes));
            exportedBlock.generate();

            // Return the ASCII bytes of the generated key block string
            return exportedBlock.toString().getBytes(StandardCharsets.US_ASCII);

        } catch (Exception e) {
            throw new SMException("Failed to export key into TR-31 key block", e);
        }
    }

    // JSecurityModuleTR31.java (Updated main method)

    public static void main(String[] args) {
        // --- 1. Setup the Security Module ---
        JSecurityModuleTR31 sm = new JSecurityModuleTR31();

        // Basic configuration for the security module
        Properties cfgProps = new Properties();
        cfgProps.setProperty("lmk", "/Volumes/SamsungT5/Transactility/jPOS/jpos/src/test/resources/org/jpos/security/lmk-test"); // Path to your LMK file
        // cfgProps.setProperty("rebuildlmk", "true");
        SimpleConfiguration cfg = new SimpleConfiguration(cfgProps);

        // Basic logging to the console
        Logger logger = new Logger();
        logger.addListener(new SimpleLogListener(System.out));
        sm.setLogger(logger, "sm-example");

        // --- Define clear keys ---
        String clearZmkHex = "0123456789ABCDEFFEDCBA9876543210";
        String clearZpkHex = "112233445566778899AABBCCDDEEFF00";

        try {
            sm.setConfiguration(cfg);
            System.out.println("JSecurityModuleTR31 initialized successfully.");
            System.out.println("--------------------------------------------------\n");

            // --- CALCULATE EXPECTED PARITY-ADJUSTED KEY (for test verification only) ---
            byte[] expectedKeyBytes = ISOUtil.hex2byte(clearZpkHex);
            Util.adjustDESParity(expectedKeyBytes);
            String expectedClearZpkHex = ISOUtil.hexString(expectedKeyBytes);

            // --- 2. Load the ZMK from clear components ---
            System.out.println("Step 1: Loading Zone Master Key (ZMK) from clear components...");
            // Use single component for simplicity, but three components would also work
            SecureDESKey zmkUnderKbpk = sm.formKEYfromClearComponents(
                    SMAdapter.LENGTH_DES3_2KEY,
                    "ZMK",
                    clearZmkHex
            );

            System.out.println("ZMK loaded and wrapped under internal KBPK:");
            System.out.println("  > KCV: " + ISOUtil.hexString(zmkUnderKbpk.getKeyCheckValue()));
            System.out.println("\n--------------------------------------------------\n");

            // --- 3. Load the ZPK from its clear value ---
            System.out.println("Step 2: Loading Zone PIN Key (ZPK) from its clear value...");

            SecureDESKey zpkUnderKbpk = sm.formKEYfromClearComponents(
                    SMAdapter.LENGTH_DES3_2KEY,
                    "ZPK",
                    clearZpkHex
            );
            System.out.println("ZPK loaded and wrapped under internal KBPK:");
            System.out.println("  > Original ZPK KCV: " + ISOUtil.hexString(zpkUnderKbpk.getKeyCheckValue()));
            System.out.println("  > Expected Parity-Adjusted Key: " + expectedClearZpkHex);
            System.out.println("\n--------------------------------------------------\n");

            // --- 4. Export the ZPK under the ZMK ---
            System.out.println("Step 3: Exporting the ZPK under the ZMK...");

            byte[] exportedZpkBlockBytes = sm.exportKey(zpkUnderKbpk, zmkUnderKbpk);
            String exportedZpkBlockUnderZmk = new String(exportedZpkBlockBytes, StandardCharsets.US_ASCII);
            System.out.println("🎉 SUCCESS! Final Key Block created for transport.");
            System.out.println("  > " + exportedZpkBlockUnderZmk);
            System.out.println("\n--------------------------------------------------\n");


            // --- 5. Reverse the process to verify correctness ---
            System.out.println("Step 4: Simulating receiving party importing the ZPK...");

            SecureDESKey importedZpkUnderKbpk = sm.importKey(
                    SMAdapter.LENGTH_DES3_2KEY,
                    "ZPK",
                    exportedZpkBlockBytes,
                    zmkUnderKbpk,
                    false
            );

            System.out.println("ZPK imported and is now wrapped under the receiver's internal KBPK:");
            System.out.println("  > Imported ZPK KCV: " + ISOUtil.hexString(importedZpkUnderKbpk.getKeyCheckValue()));
            System.out.println();

            // Verification 1: Compare KCVs (The main verification)
            if (ISOUtil.hexString(zpkUnderKbpk.getKeyCheckValue()).equals(ISOUtil.hexString(importedZpkUnderKbpk.getKeyCheckValue()))) {
                System.out.println("✅ KCV Verification PASSED: The imported key is correct.");
            } else {
                System.err.println("❌ KCV Verification FAILED!");
            }

            // Verification 2: Decrypt and compare clear values against the EXPECTED parity-adjusted key.
            Key finalClearZpk = sm.decryptFromLMK(importedZpkUnderKbpk);
            String finalClearZpkHex = ISOUtil.hexString(sm.jceHandler.extractDESKeyMaterial(importedZpkUnderKbpk.getKeyLength(), finalClearZpk));

            if (expectedClearZpkHex.equalsIgnoreCase(finalClearZpkHex)) {
                System.out.println("✅ Clear Key Verification PASSED: The decrypted key matches the original (parity-adjusted).");
                System.out.println("  > Expected Clear ZPK: " + expectedClearZpkHex);
                System.out.println("  > Final Clear ZPK:    " + finalClearZpkHex);
            } else {
                System.err.println("❌ Clear Key Verification FAILED!");
                System.err.println("  > Expected Clear ZPK: " + expectedClearZpkHex);
                System.err.println("  > Final Clear ZPK:    " + finalClearZpkHex);
            }

        } catch (Exception e) {
            System.err.println("An error occurred during the key management process.");
            e.printStackTrace();
        }
    }
}