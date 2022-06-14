package com.example.newoma;

import android.util.Log;

// this is for scp03
public class MyKeys2 {
    private static final String TAG = ".MyKeys2";

    private MyKeys2() {
    }

    private static final String encKey = "404142434445464748494A4B4C4D4E4F";
    private static final String macKey = "404142434445464748494A4B4C4D4E4F";
    private static final String decKey = "404142434445464748494A4B4C4D4E4F";
    // Host challenge
    private static final String random = "0102030405060708";
    private static final String keyVersion = "30";
    private static final String securityLevel = "01";

    public static byte[] selISD() {
        String str = "00A4040008A00000015100000000";
        return MyUtils.hexStrToByteArray(str);
    }

    public static boolean processSelISD(byte[] resp) {
        if (resp == null || resp.length < 2) {
            Log.d(TAG, "processSelISD: response len wrong");
            return false;
        }
        if (resp[resp.length - 2] == (byte) 0x90 && resp[resp.length - 1] == 0x00) {
            return true;
        }
        Log.d(TAG, "processSelISD: status code wrong");
        return false;
    }

    public static byte[] initUpdate() {
        // fix Host challenge = 0102030405060708
        String str = "8050" + keyVersion + "0008" + random + "00";
        return MyUtils.hexStrToByteArray(str);
    }

    private static final byte[] keyDiversificationData = new byte[10];
    private static final byte[] keyInformation = new byte[3];
    private static final byte[] cardChallenge = new byte[8];
    private static final byte[] cardCryptogram = new byte[8];
    private static final byte[] sequenceCounter = new byte[3];

    public static boolean processInitUpdate(byte[] resp) {
        if (resp == null || resp.length < 34) {
            Log.d(TAG, "processInitUpdate: response len wrong");
            return false;
        }
        if (resp[resp.length - 2] != (byte) 0x90 || resp[resp.length - 1] != 0x00) {
            Log.d(TAG, "processInitUpdate: status code wrong");
            return false;
        }

        System.arraycopy(resp, 0, keyDiversificationData, 0, 10);
        System.arraycopy(resp, 10, keyInformation, 0, 3);
        System.arraycopy(resp, 13, cardChallenge, 0, 8);
        System.arraycopy(resp, 21, cardCryptogram, 0, 8);
        System.arraycopy(resp, 29, sequenceCounter, 0, 3);
        Log.d(TAG, "keyDiversificationData: " + MyUtils.byteArrayToHexStr2(keyDiversificationData));
        Log.d(TAG, "keyInformation: " + MyUtils.byteArrayToHexStr2(keyInformation));
        Log.d(TAG, "cardChallenge: " + MyUtils.byteArrayToHexStr2(cardChallenge));
        Log.d(TAG, "cardCryptogram: " + MyUtils.byteArrayToHexStr2(cardCryptogram));
        Log.d(TAG, "sequenceCounter: " + MyUtils.byteArrayToHexStr2(sequenceCounter));

        Log.d(TAG, "processInitUpdate: success");
        return true;
    }

    public static byte[] extAuthCmd() {
        getSessionKeys();
        String hostCryptogram = getHostCryptogram();
        Log.d(TAG, "extAuthCmd: hostCryptogram = " + hostCryptogram);

        String str = "8482" + securityLevel + "0010";
        String cMac = getCmac(str + hostCryptogram);

        Log.d(TAG, "extAuthCmd: cMac = " + cMac);
        str += hostCryptogram + cMac;
        Log.d(TAG, "extAuthCmd: " + str);
        return MyUtils.hexStrToByteArray(str);
    }

    static byte[] s_mac = new byte[16];
    static byte[] s_enc = new byte[16];

    private static void getSessionKeys() {
        // calc enc session key
        String str = "00000000000000000000" +
                "000400008001" +
                random +
                MyUtils.byteArrayToHexStr2(cardChallenge);
        byte[] input1 = MyUtils.hexStrToByteArray(str);
        Log.d(TAG, "getSessionKeys: input = " + MyUtils.byteArrayToHexStr2(input1));
        s_enc = MyAlgo.calc_aes_cbc_mac(input1, null, MyUtils.hexStrToByteArray(encKey));
        Log.d(TAG, "getSessionKeys: s_enc = " + MyUtils.byteArrayToHexStr2(s_enc));

        // calc mac session key
        String str2 = "00000000000000000000" +
                "000600008001" +
                random +
                MyUtils.byteArrayToHexStr2(cardChallenge);
        byte[] input2 = MyUtils.hexStrToByteArray(str2);
        Log.d(TAG, "getSessionKeys: input2 = " + MyUtils.byteArrayToHexStr2(input2));
        s_mac = MyAlgo.calc_aes_cbc_mac(input2, null, MyUtils.hexStrToByteArray(macKey));
        Log.d(TAG, "getSessionKeys: s_mac = " + MyUtils.byteArrayToHexStr2(s_mac));
    }

    private static String getCmac(String text) {

        byte[] input = MyUtils.hexStrToByteArray(text);
        Log.d(TAG, "getCmac: input = " + MyUtils.byteArrayToHexStr2(input));

        byte[] iv = new byte[16];
        byte[] cMac = MyAlgo.calc_aes_cbc_mac(input, iv, s_mac);
        Log.d(TAG, "getCmac: cMac = " + MyUtils.byteArrayToHexStr2(cMac));

        return MyUtils.byteArrayToHexStr2(cMac).substring(0, 16);
    }

    private static String getHostCryptogram() {
        String str = "00000000000000000000" +
                "000100004001" +
                random +
                MyUtils.byteArrayToHexStr2(cardChallenge);
        byte[] input = MyUtils.hexStrToByteArray(str);
        Log.d(TAG, "getHostCryptogram: input = " + MyUtils.byteArrayToHexStr2(input));

        byte[] hostCryptogram = MyAlgo.calc_aes_cbc_mac(input, null, s_mac);
        Log.d(TAG, "getHostCryptogram: " + MyUtils.byteArrayToHexStr2(hostCryptogram));

        return MyUtils.byteArrayToHexStr2(hostCryptogram).substring(0, 16);
    }

    public static boolean processExtAuthCmd(byte[] resp) {
        if (resp == null || resp.length < 2) {
            Log.d(TAG, "processExtAuthCmd: response len wrong");
            return false;
        }
        if (resp[resp.length - 2] == (byte) 0x90 && resp[resp.length - 1] == 0x00) {
            return true;
        }
        Log.d(TAG, "processExtAuthCmd: status word wrong");
        return false;
    }
}
