/*
 * jPOS Project [http://jpos.org]
 * Copyright (C) 2000-2024 jPOS Software SRL
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package org.jpos.security.jceadapter;

import org.jpos.core.ConfigurationException;
import org.jpos.core.SimpleConfiguration;
import org.jpos.iso.ISOUtil;
import org.jpos.security.jceadapter.KeyConverter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.jpos.util.Logger;
import org.jpos.util.SimpleLogListener;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * A simple application for sending critical commands to the JCE Security
 * Module.
 * The functionalities available from this console, are not available
 * programmatically (via API's),
 * for security reasons, because most of them involve clear (non encrypted)
 * keys.
 * Those commands are package protected in the JCE Security Module.
 * 
 * @author Hani Samuel Kirollos
 * @version $Revision$ $Date$
 */
public class Console {

    public Console() {
    }

    /**
     * @param args
     */
    public static void main(String[] args) throws ConfigurationException {
        new Console().exec(System.out, System.err, args);
    }

    public void exec(PrintStream outPS, PrintStream errPS, String[] args) throws ConfigurationException {
        // Default to the base module
        JCESecurityModule sm      = new JCESecurityModule();
        boolean           useTr31 = false;

        Logger logger = new Logger();
        logger.addListener(new SimpleLogListener(outPS));
        Properties          cfgProps      = new Properties();
        SimpleConfiguration cfg           = new SimpleConfiguration(cfgProps);
        String              commandName   = null;
        String[]            commandParams = new String[10];                   // 10
                                                                              // is
                                                                              // Maximum
                                                                              // number
                                                                              // of
                                                                              // paramters
                                                                              // for
                                                                              // a
                                                                              // command

        if (args.length == 0) {
            printUsage(outPS);
            return;
        }

        // --- Argument Parsing ---
        int argsCounter = 0;
        while (argsCounter < args.length) {
            String arg = args[argsCounter].toLowerCase();
            if (arg.equals("-lmk")) {
                argsCounter++;
                if (argsCounter < args.length) {
                    cfgProps.setProperty("lmk", args[argsCounter++]);
                }
            }
            else if (arg.equals("-jce")) {
                argsCounter++;
                if (argsCounter < args.length) {
                    cfgProps.setProperty("provider", args[argsCounter++]);
                }
            }
            else if (arg.equals("-rebuildlmk")) {
                argsCounter++;
                cfgProps.setProperty("rebuildlmk", "true");
            }
            else if (arg.equals("-tr31")) { // New flag for TR-31 module
                argsCounter++;
                useTr31 = true;
            }
            else {
                // First non-option argument is the command
                break;
            }
        }

        if (argsCounter < args.length) {
            commandName = args[argsCounter++];
            int i = 0;
            while (argsCounter < args.length) {
                commandParams[i++] = args[argsCounter++];
            }
        }

        if (commandName == null && !cfgProps.containsKey("rebuildlmk")) {
            errPS.println("No command specified.");
            printUsage(errPS);
            return;
        }

        outPS.println("Welcome to JCE Security Module console commander!");
        if (useTr31) {
            outPS.println("Mode: TR-31 Key Management Enabled");
            sm = new JSecurityModuleTR31();
        }
        else {
            outPS.println("Mode: Legacy LMK Variant Scheme");
        }

        sm.setLogger(logger, "jce-security-module-console");

        // Configure JCE Security Module
        try {
            sm.setConfiguration(cfg);
        }
        catch (ConfigurationException e) {
            e.printStackTrace(errPS);
            return;
        }

        // Execute Command
        if (commandName != null) {
            try {
                if (commandName.equalsIgnoreCase("GC")) {
                    short  keyLength         = (short) Integer.parseInt(commandParams[0]);
                    String clearKeyComponent = sm.generateClearKeyComponent(keyLength);
                    outPS.println("Generated Clear Key Component: " + clearKeyComponent);
                }
                else if (commandName.equalsIgnoreCase("FK")) {
                    short        keyLength   = (short) Integer.parseInt(commandParams[0]);
                    String       keyType     = commandParams[1].toUpperCase();
                    SecureDESKey keyUnderLMK = sm.formKEYfromThreeClearComponents(keyLength, keyType, commandParams[2],
                                                                                  commandParams[3], commandParams[4]);
                    outPS.println("Formed Key under LMK:");
                    outPS.println("  Key Type: " + keyUnderLMK.getKeyType());
                    outPS.println("  Key Check Value: " + ISOUtil.hexString(keyUnderLMK.getKeyCheckValue()));
                    String keyData = useTr31 ? new String(keyUnderLMK.getKeyBytes(), StandardCharsets.US_ASCII)
                            : ISOUtil.hexString(keyUnderLMK.getKeyBytes());
                    outPS.println("  Key Data (under LMK): " + keyData);
                }
                else if (commandName.equalsIgnoreCase("CK")) {
                    short  keyLength       = (short) Integer.parseInt(commandParams[0]);
                    String keyType         = commandParams[1].toUpperCase();
                    String keyUnderLmkData = commandParams[2];
                    byte[] keyBytes        = useTr31 ? keyUnderLmkData.getBytes(StandardCharsets.US_ASCII)
                            : ISOUtil.hex2byte(keyUnderLmkData);

                    byte[] keyCheckValue = sm.generateKeyCheckValue(new SecureDESKey(keyLength, keyType, keyBytes,
                                                                                     new byte[0])); // KCV
                                                                                                    // not
                                                                                                    // needed
                                                                                                    // for
                                                                                                    // this
                                                                                                    // op
                    outPS.println("Generated Key Check Value: " + ISOUtil.hexString(keyCheckValue));
                }
                else if (commandName.equalsIgnoreCase("IK")) { // Legacy Import
                    if (useTr31) {
                        errPS.println("Command IK is for legacy mode. Use IKT for TR-31 mode.");
                        return;
                    }
                    short        keyLength   = (short) Integer.parseInt(commandParams[0]);
                    SecureDESKey kekUnderLMK = new SecureDESKey((short) Integer.parseInt(commandParams[3]),
                                                                commandParams[4].toUpperCase(), commandParams[5],
                                                                commandParams[6]);
                    SecureDESKey importedKey = sm.importKey(keyLength, commandParams[1].toUpperCase(),
                                                            ISOUtil.hex2byte(commandParams[2]), kekUnderLMK, true);
                    outPS.println("Imported Key under LMK (Legacy): " + ISOUtil.hexString(importedKey.getKeyBytes()));
                    outPS.println("  KCV: " + ISOUtil.hexString(importedKey.getKeyCheckValue()));
                }
                else if (commandName.equalsIgnoreCase("IKT")) { // TR-31 Import
                    if (!useTr31) {
                        errPS.println("Command IKT requires -tr31 flag.");
                        return;
                    }
                    short  keyLength        = (short) Integer.parseInt(commandParams[0]);
                    String keyType          = commandParams[1].toUpperCase();
                    String keyBlock         = commandParams[2];
                    short  kekLength        = (short) Integer.parseInt(commandParams[3]);
                    String kekType          = commandParams[4].toUpperCase();
                    String kekUnderLmkBlock = commandParams[5];
                    String kekKcvHexString  = commandParams[6];

                    // CORRECTED: Convert both key data and KCV to byte arrays
                    byte[]       kekBytes    = kekUnderLmkBlock.getBytes(StandardCharsets.US_ASCII);
                    byte[]       kekKcvBytes = ISOUtil.hex2byte(kekKcvHexString);
                    SecureDESKey kek         = new SecureDESKey(kekLength, kekType, kekBytes, kekKcvBytes);

                    SecureDESKey importedKey = sm.importKey(keyLength, keyType,
                                                            keyBlock.getBytes(StandardCharsets.US_ASCII), kek, true);

                    outPS.println("Successfully imported TR-31 Key Block.");
                    outPS.println("  Imported Key under LMK: "
                            + new String(importedKey.getKeyBytes(), StandardCharsets.US_ASCII));
                    outPS.println("  KCV: " + ISOUtil.hexString(importedKey.getKeyCheckValue()));
                }
                else if (commandName.equalsIgnoreCase("KE")) { // Legacy Export
                    if (useTr31) {
                        errPS.println("Command KE is for legacy mode. Use KET for TR-31 mode.");
                        return;
                    }
                    short        keyLength   = (short) Integer.parseInt(commandParams[0]);
                    SecureDESKey kekUnderLMK = new SecureDESKey((short) Integer.parseInt(commandParams[4]),
                                                                commandParams[5].toUpperCase(), commandParams[6],
                                                                commandParams[7]);
                    SecureDESKey keyUnderLMK = new SecureDESKey(keyLength, commandParams[1].toUpperCase(),
                                                                commandParams[2], commandParams[3]);
                    byte[]       exportedKey = sm.exportKey(keyUnderLMK, kekUnderLMK);
                    outPS.println("Exported Key under KEK (Legacy): " + ISOUtil.hexString(exportedKey));
                }
                else if (commandName.equalsIgnoreCase("KET")) { // TR-31 Export
                    if (!useTr31) {
                        errPS.println("Command KET requires -tr31 flag.");
                        return;
                    }
                    short  keyLength        = (short) Integer.parseInt(commandParams[0]);
                    String keyType          = commandParams[1].toUpperCase();
                    String keyUnderLmkBlock = commandParams[2];
                    String keyKcvHexString  = commandParams[3];

                    short  kekLength        = (short) Integer.parseInt(commandParams[4]);
                    String kekType          = commandParams[5].toUpperCase();
                    String kekUnderLmkBlock = commandParams[6];
                    String kekKcvHexString  = commandParams[7];

                    // CORRECTED: Convert both key data and KCVs to byte arrays
                    // for both keys
                    byte[]       keyBytes    = keyUnderLmkBlock.getBytes(StandardCharsets.US_ASCII);
                    byte[]       keyKcvBytes = ISOUtil.hex2byte(keyKcvHexString);
                    SecureDESKey key         = new SecureDESKey(keyLength, keyType, keyBytes, keyKcvBytes);

                    byte[]       kekBytes    = kekUnderLmkBlock.getBytes(StandardCharsets.US_ASCII);
                    byte[]       kekKcvBytes = ISOUtil.hex2byte(kekKcvHexString);
                    SecureDESKey kek         = new SecureDESKey(kekLength, kekType, kekBytes, kekKcvBytes);

                    byte[] exportedKeyBlock = sm.exportKey(key, kek);
                    outPS.println("Exported TR-31 Key Block: "
                            + new String(exportedKeyBlock, StandardCharsets.US_ASCII));
                }
                else if (commandName.equalsIgnoreCase("CVT")) {
                    String direction     = commandParams[0];
                    short  keyLength     = Short.parseShort(commandParams[1]);
                    String keyType       = commandParams[2].toUpperCase();
                    String sourceKeyData = commandParams[3];

                    // Both modules need to be initialized for conversion
                    JCESecurityModule variantModule = new JCESecurityModule();
                    variantModule.setLogger(logger, "jce-security-module-console");
                    variantModule.setConfiguration(cfg);

                    JSecurityModuleTR31 tr31Module = new JSecurityModuleTR31();
                    tr31Module.setLogger(logger, "jce-security-module-console");
                    tr31Module.setConfiguration(cfg);

                    KeyConverter converter = new KeyConverter(variantModule, tr31Module);
                    SecureDESKey sourceKey;
                    SecureDESKey convertedKey;

                    if ("variant-to-tr31".equalsIgnoreCase(direction)) {
                        outPS.println("Converting Legacy Variant key to TR-31 Key Block...");
                        byte[] keyBytes = ISOUtil.hex2byte(sourceKeyData);
                        sourceKey = new SecureDESKey(keyLength, keyType, keyBytes, new byte[0]);
                        convertedKey = converter.convertVariantToTR31(sourceKey);

                        outPS.println("Conversion Successful.");
                        outPS.println("  Original KCV: "
                                + ISOUtil.hexString(variantModule.generateKeyCheckValue(sourceKey)));
                        outPS.println("  Converted Key (TR-31 Block): "
                                + new String(convertedKey.getKeyBytes(), StandardCharsets.US_ASCII));
                        outPS.println("  Converted KCV: " + ISOUtil.hexString(convertedKey.getKeyCheckValue()));

                    }
                    else if ("tr31-to-variant".equalsIgnoreCase(direction)) {
                        outPS.println("Converting TR-31 Key Block to Legacy Variant key...");
                        byte[] keyBytes = sourceKeyData.getBytes(StandardCharsets.US_ASCII);
                        sourceKey = new SecureDESKey(keyLength, keyType, keyBytes, new byte[0]);
                        convertedKey = converter.convertTR31ToVariant(sourceKey);

                        outPS.println("Conversion Successful.");
                        outPS.println("  Original KCV: "
                                + ISOUtil.hexString(tr31Module.generateKeyCheckValue(sourceKey)));
                        outPS.println("  Converted Key (Variant Hex): "
                                + ISOUtil.hexString(convertedKey.getKeyBytes()));
                        outPS.println("  Converted KCV: " + ISOUtil.hexString(convertedKey.getKeyCheckValue()));

                    }
                                        // *** ADDED THIS ELSE BLOCK ***
                    else {
                        errPS.println("Invalid direction for CVT command. Use 'variant-to-tr31' or 'tr31-to-variant'.");
                        printUsage(errPS);
                    }

                }
                else {
                    errPS.println("Unknown command: " + commandName);
                    printUsage(errPS);
                }
            }
            catch (SMException e) {
                e.printStackTrace(errPS);
            }
            catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
                errPS.println("Invalid or missing parameters for command: " + commandName);
                printUsage(errPS);
            }
        }
    }

    private void printUsage(PrintStream ps) {
        ps.println("\nUsage: Console [-options] command [commandparameters...]");
        ps.println("\nOptions include:");
        ps.println("    -lmk <filename>        Specify the Local Master Keys file");
        ps.println("    -rebuildlmk            Rebuild new Local Master Keys (WARNING: overwrites old file)");
        ps.println("    -jce <provider class>  Specify a JCE provider");
        ps.println("    -tr31                  Enable TR-31 key block mode (uses JSecurityModuleTR31)");
        ps.println("\nCommands include:");
        ps.println("  Legacy Mode Commands:");
        ps.println("    GC <keyLength>");
        ps.println("          Generate a clear key component.");
        ps.println("    FK <keyLength> <keyType> <comp1> [<comp2>] [<comp3>]");
        ps.println("          Form a key from components and encrypt under LMK.");
        ps.println("    CK <keyLength> <keyType> <KEYunderLMK_Hex>");
        ps.println("          Generate a key check value for a key encrypted under LMK.");
        ps.println("    IK <keyLen> <keyType> <KEYunderKEK_Hex> <kekLen> <kekType> <KEKunderLMK_Hex> <KEK_KCV>");
        ps.println("          Import a key from KEK to LMK encryption.");
        ps.println("    KE <keyLen> <keyType> <KEYunderLMK_Hex> <KEY_KCV> <kekLen> <kekType> <KEKunderLMK_Hex> <KEK_KCV>");
        ps.println("          Export a key from LMK to KEK encryption.");
        ps.println("\n  TR-31 Mode Commands (-tr31 flag required):");
        ps.println("    FK, GC, CK work as above but will produce/consume TR-31 blocks for KEYunderLMK.");
        ps.println("    IKT <keyLen> <keyType> <TR31_KeyBlock> <kekLen> <kekType> <KEKunderLMK_Block> <KEK_KCV_Hex>");
        ps.println("          Import a key from a TR-31 key block.");
        ps.println("    KET <keyLen> <keyType> <KEYunderLMK_Block> <KEY_KCV_Hex> <kekLen> <kekType> <KEKunderLMK_Block> <KEK_KCV_Hex>");
        ps.println("          Export a key from LMK into a new TR-31 key block.");
        ps.println("\n  Interoperability Commands:");
        ps.println("    CVT <direction> <keyLen> <keyType> <sourceKeyData>");
        ps.println("          Convert a key between variant and TR-31 formats.");
        ps.println("          <direction> can be 'variant-to-tr31' or 'tr31-to-variant'.");
        ps.println("          <sourceKeyData> is a hex string for variant, or a TR-31 block (in quotes) for TR-31.");

    }
}