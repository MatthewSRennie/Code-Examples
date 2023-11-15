/**
 * Created by Matt Rennie
 * 2/28/20
 * COMP 4705
 * Project 2 - Variable Length RSA
 * 
 * This program can be used to encrypt a variable length RSA message (as opposed to the typical fixed length)
 * To use, simply run the program
 * You can either specify your own keys, or generate keys using the program
 */

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.lang.System;

public class VariableLengthRSA {
    public static final int BIT_LENGTH = 2048; // must be multiple of 8
    public static final int PRIMALITY_TEST_ITERATIONS = 100;
    public static final int BLOCK_SIZE = 214; // 214 as required by the program specifications
    public static final int GEN_LENGTH = (BIT_LENGTH/2);
    public static final boolean VERBOSE_OUTPUT = false;

    private Random rand;
    private BigInteger primeP;
    private BigInteger primeQ;
    private BigInteger n;
    private BigInteger phiN;
    private BigInteger e;
    private BigInteger eInv;

    public VariableLengthRSA() {
        this("null", "null", "null");
    }

    public VariableLengthRSA(String primesFile, String publicKeyFile, String privateKeyFile) {
        if (BLOCK_SIZE > BIT_LENGTH/8) {
            System.out.println("Invalid block size for given bit length. Largest valid block size is: " + BIT_LENGTH/8);
            System.exit(1);
        }
        int randSeed = new Random().nextInt();
        rand = new Random(randSeed);

        if (VERBOSE_OUTPUT)
            System.out.println("Rand seed: " + randSeed);

        if (primesFile.equals("null")) {
            primeP = generatePrime(GEN_LENGTH, rand);
            primeQ = generatePrime(GEN_LENGTH, rand);
        }
        else {
            if (checkForFile(primesFile)) {
                String[] fileContents = readFromFile(primesFile).split("\n");
                primeP = new BigInteger(fileContents[0]);
                primeQ = new BigInteger(fileContents[1]);
            }
            else {
                primeP = generatePrime(GEN_LENGTH, rand);
                primeQ = generatePrime(GEN_LENGTH, rand);
                writeToFile(primesFile, primeP + "\n" + primeQ);
            }
        }

        if (!primeP.isProbablePrime(100) || !primeQ.isProbablePrime(100)) {
            System.out.println("Error: Prime test may be incorrect");
        }

        System.out.println("P: " + primeP);
        System.out.println("Q: " + primeQ);
        n = primeP.multiply(primeQ);
        phiN = (primeP.subtract(BigInteger.ONE)).multiply(primeQ.subtract(BigInteger.ONE));
        e = generateE(phiN, rand);
        eInv = inverse_mod_n(e, phiN);
        if (!publicKeyFile.equals("null")) {
            writeToFile(publicKeyFile, n + "\n" + e);
        }
        if (!privateKeyFile.equals("null")) {
            writeToFile(privateKeyFile, n + "\n" + eInv);
        }

        if ((e.multiply(eInv)).mod(phiN).compareTo(BigInteger.ONE) != 0) {
            System.out.println("Error generating eInv. Should be: " + e.modInverse(phiN));
            System.exit(1);
        }

        System.out.println("n: " + n);
        System.out.println("e: " + e);
        System.out.println("d (eInv): " + eInv);
    }

    /*** UTILITY FUNCTIONS ***/

    public static String bigIntToStr(BigInteger num) {
        return new String(num.toByteArray());
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (a.compareTo(BigInteger.ZERO) == 0) {
            return b;
        }
        return gcd(b.mod(a), a);
    }

    public static BigInteger square_and_multiply(BigInteger b, BigInteger e, BigInteger m) {
        BigInteger z = new BigInteger("1");
        while (e.compareTo(BigInteger.ZERO) > 0) {
            if ((e.mod(BigInteger.TWO)).compareTo(BigInteger.ONE) == 0) {
                z = (z.multiply(b)).mod(m);
            }
            e = e.shiftRight(1);
            b = (b.multiply(b)).mod(m);
        }
        return z;
    }

    public static BigInteger inverse_mod_n(BigInteger num, BigInteger mod) {
        num = num.mod(mod);

        BigInteger t = new BigInteger("0");
        BigInteger newt = new BigInteger("1");
        BigInteger r = new BigInteger(mod.toString()); // no copy constructor for some reason?
        BigInteger newr = new BigInteger(num.toString());
        BigInteger quo;

        while (newr.compareTo(BigInteger.ZERO) != 0) {
            quo = r.divide(newr);
            BigInteger temp = newr;
            newr = r.subtract(quo.multiply(newr));
            r = temp;
            temp = newt;
            newt = t.subtract(quo.multiply(newt));
            t = temp;
        }

        if (r.compareTo(BigInteger.ONE) > 1) {
            System.out.println("Error finding inverse");
            System.exit(1);
            return new BigInteger("-1");
        }
        if (t.compareTo(BigInteger.ZERO) < 1) {
            t = t.add(mod);
        }

        return t;
    }

    private static byte[] trimArr(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && (((int) bytes[i]) == 0)) {
            i--;
        }
        return Arrays.copyOf(bytes, i + 1);
    }

    private static byte[] removeSignBit(byte[] bytes) {
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // Source: https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public void printPublicKey() {
        System.out.println("Public Key: (" + n + ", " + e + ")");
    }

    public void printPrivateKey() {
        System.out.println("Private Key: (" + eInv + ")");
    }

    public static boolean writeToFile(String fileName, String data) {
        Path file = Paths.get(fileName);
        try {
            Files.write(file, data.getBytes(), StandardOpenOption.CREATE);
        }
        catch (Exception e) {
            System.out.println("Error writing to file");
            return false;
        }
        return true;
    }

    public static String readFromFile(String fileName) {
        Path file = Paths.get(fileName);
        byte[] fileArray;
        try {
            fileArray = Files.readAllBytes(file);
        }
        catch (Exception e) {
            System.out.println("Error reading from file");
            return null;
        }
        return new String(fileArray);
    }

    public static boolean checkForFile(String fileName) {
        Path file = Paths.get(fileName);
        if (Files.exists(file)) {
            return true;
        }
        return false;
    }

    // Source: https://stackoverflow.com/questions/6827516/logarithm-for-biginteger
    public static double logBigInteger(BigInteger val) {
        if (val.signum() < 1)
            return val.signum() < 0 ? Double.NaN : Double.NEGATIVE_INFINITY;
        int blex = val.bitLength() - BIT_LENGTH/2; // any value in 60..1023 works here
        if (blex > 0)
            val = val.shiftRight(blex);
        double res = Math.log(val.doubleValue());
        return blex > 0 ? res + blex * Math.log(2.0) : res;
    }

    /*** END UTILITY FUNCTIONS ***/

    /*** NUMBER GENERATION ***/

    public static BigInteger generatePrime(int length, Random rand) {
        BigInteger num;
        int i = 0;
        do {
            i++;
            num = new BigInteger(length, rand);
        }while (!solovayStrassenPrimalityTest(num, PRIMALITY_TEST_ITERATIONS, rand));
        System.out.println("Prime generated after trying " + i + " numbers.");
        System.out.println("Tested using the Solovay-Strassen primality test " + PRIMALITY_TEST_ITERATIONS + " times.");
        System.out.println("Probability it is not prime is: " + solovoyStrassenAccuracy(num));
        return num;
    }

    public static int jacobi(BigInteger a, BigInteger n) {
        if (gcd(a,n).compareTo(BigInteger.ONE) != 0) {
            return -2;
        }
        return jacobiAux(a, n, 1);
    }

    public static int jacobiAux(BigInteger a, BigInteger n, int negative) {
        a = a.mod(n); // rule 1

        if (a.compareTo(BigInteger.ZERO) == 0) { // base case
            return negative;
        }

        while (a.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) { // rule 2
            if (a.compareTo(BigInteger.ZERO) == 0) return -2;
            a = a.divide(BigInteger.TWO);
            if (n.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(3)) == 0 || n.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(5)) == 0)
                negative *= -1;
        }

        if (a.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0 && n.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0) {// rule 5
            negative *= -1;
        }

        return jacobiAux(n, a, negative);
    }

    public static BigInteger generateE(BigInteger phiN, Random rand) {
        BigInteger e;

        // check a couple commonly used values for e, which will run more quickly, if not coprime generate one
        // currently not using because of the program specifications, and because 3 is less secure (although faster)
//      if (gcd(phiN, BigInteger.valueOf(3)).compareTo(BigInteger.ONE) == 0)
//          return new BigInteger("3");

//      if (gcd(phiN, BigInteger.valueOf(65537)).compareTo(BigInteger.ONE) == 0)
//          return new BigInteger("65537");

        do {
            e = new BigInteger(phiN.bitLength(), rand);
            e = e.mod(phiN);
        } while(gcd(e, phiN).compareTo(BigInteger.ONE) != 0);
        return e;
    }

    // not used but left it in as an alternative primality test
    public static boolean fermatPrimalityTest(BigInteger num, int iterations, Random rand) {
        // zero/one are not prime numbers
        if (num.compareTo(BigInteger.ZERO) == 0 || num.compareTo(BigInteger.ONE) == 0)
            return false;

        // two is a prime number, but multiples of 2 aren't so I will check for it separately
        if (num.compareTo(BigInteger.TWO) == 0)
            return true;

        // if it is divisible by 2 (and not the number 2, check above) it is not prime
        if (num.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0)
            return false;

        BigInteger randomA;

        for (int i = 0; i < iterations; i++) {
            randomA = new BigInteger(BIT_LENGTH, rand); // generates a random BigInteger (evenly distributed) of size BIT_LENGTH
            randomA = randomA.mod(num.subtract(BigInteger.ONE)).add(BigInteger.ONE); // needs to be in the range 1 < a < n
            if (square_and_multiply(randomA, num.subtract(BigInteger.ONE),num).compareTo(BigInteger.ONE) != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean solovayStrassenPrimalityTest(BigInteger p, int iterations, Random rand) {
        if (p.compareTo(BigInteger.TWO) < 0)
            return false;

        if (p.compareTo(BigInteger.TWO) != 0 && p.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0)
            return false;

        for (int i = 0; i < iterations; i++) {
            BigInteger randomA = new BigInteger(BIT_LENGTH, rand); // generates a random BigInteger (evenly distributed) of size BIT_LENGTH
            randomA = randomA.mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE); // make sure it is in the correct range
            BigInteger jacobian = (p.add(BigInteger.valueOf(jacobi(randomA,p)))).mod(p); // calculate jacobi syjmbol value
            BigInteger mod = square_and_multiply(randomA, p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p); // calc a^(n-1)/2 mod n
            if (jacobian.compareTo(BigInteger.ZERO) == 0 || mod.compareTo(jacobian) != 0)
                return false;
        }
        return true;
    }

    public static double solovoyStrassenAccuracy(BigInteger n) {
        double logN = logBigInteger(n);
        logN = (logN - 2.0) / (logN - 2.0 + Math.pow(2, PRIMALITY_TEST_ITERATIONS - 1));
        return logN;
    }

    /*** END NUMBER GENERATION ***/

    /*** ENCRYPTION ***/

    public BigInteger encrypt(String str) {
        return encrypt(str, n, e);
    }

    public static BigInteger encrypt(String str, BigInteger n, BigInteger e) {
        BigInteger num = new BigInteger(str.getBytes());
        return encrypt(num, n, e);
    }

    public BigInteger encrypt(BigInteger num) {
        return encrypt(num, n, e);
    }

    public static BigInteger encrypt(BigInteger num, BigInteger n, BigInteger e) {
        byte[] numByteArr = num.toByteArray();
        numByteArr = removeSignBit(numByteArr); // remove sign bit, will not change if not needed
        int toPad = (BLOCK_SIZE - (numByteArr.length % BLOCK_SIZE)) % BLOCK_SIZE;
        int numBlocks = (numByteArr.length + toPad) / BLOCK_SIZE;
        if (VERBOSE_OUTPUT) {
            System.out.println("Encrypting");
            System.out.println("To pad: " + toPad);
            System.out.println("Num Blocks: " + numBlocks);
            System.out.println("Unencoded text: " + num);
        }
        if (toPad != 0) { // pad if necessary
            if (VERBOSE_OUTPUT)
                System.out.println("Padding added (overall)");
            numByteArr = Arrays.copyOf(numByteArr, numByteArr.length + toPad);
        }

        if (VERBOSE_OUTPUT)
            System.out.println("Total length: " + numByteArr.length);

        // changed from BLOCK_SIZE to BIT_LENGTH/8 because the resulting length will not be BLOCK_SIZE
        byte[] resultByteArr = new byte[numBlocks * BIT_LENGTH/8];

        for (int i = 0; i < numBlocks; i++) {
            num = new BigInteger(1, Arrays.copyOfRange(numByteArr, i * BLOCK_SIZE, (i+1) * BLOCK_SIZE));
            if (VERBOSE_OUTPUT) {
                System.out.println("Range: " + i * BLOCK_SIZE + " - " + (i + 1) * BLOCK_SIZE);
                System.out.println("Enc before s&m: " + num);
                System.out.println("Enc s&m test1: " + num.modPow(e, n));
            }

            BigInteger numTest = num.modPow(e,n);
            num = square_and_multiply(num, e, n);
            if (num.compareTo(numTest) != 0) {
                System.out.println("Error: square and multiply is incorrect");
            }
            byte[] toCopy = num.toByteArray();
            toCopy = removeSignBit(toCopy); // remove sign bit, will not change if not needed

            if (VERBOSE_OUTPUT) {
                System.out.println("num.toByteArray() Hex: " + bytesToHex(num.toByteArray()));
                System.out.println("Enc after s&m: " + num);
                //System.out.println("Enc s&m test2: " + num.modPow(eInv, n));
            }

            // pad block
            if (toCopy.length < BIT_LENGTH/8) { // changed from BLOCK_SIZE to BIT_LENGTH/8 because the resulting length will not be BLOCK_SIZE
                if (VERBOSE_OUTPUT)
                    System.out.println("Padding added (block)");
                toCopy = Arrays.copyOf(toCopy, BIT_LENGTH/8);
            }

            if (VERBOSE_OUTPUT) {
                System.out.println("toCopy Hex: " + bytesToHex(toCopy));
                System.out.println("toCopy length: " + toCopy.length);
                System.out.println("resultByteArr length: " + resultByteArr.length);
                System.out.println("start index: " + i * BIT_LENGTH / 8);
                System.out.println("length to copy: " + BIT_LENGTH / 8);
                System.out.println("n length: " + n.toByteArray().length);
            }

            System.arraycopy(toCopy, 0, resultByteArr, i*BIT_LENGTH/8, BIT_LENGTH/8);
            if (VERBOSE_OUTPUT) {
                System.out.println("Should be: " + new BigInteger(1, toCopy));
                System.out.println("Might be: " + new BigInteger(1, trimArr(toCopy)));
                System.out.println("Current resultByteArr: " + new BigInteger(1, trimArr(resultByteArr)));
                System.out.println("Current resultByteArr Length: " + trimArr(resultByteArr).length);
            }
        }
        if (VERBOSE_OUTPUT)
            System.out.println("resultByteArr Hex: " + bytesToHex(resultByteArr));

        return new BigInteger(1, resultByteArr);
    }

    public BigInteger decrypt(BigInteger num) {
        return decrypt(num, n, eInv);
    }

    public static BigInteger decrypt(BigInteger num, BigInteger n, BigInteger eInv) {
        byte[] numByteArr = num.toByteArray();
        numByteArr = removeSignBit(numByteArr); // remove sign bit
        int numBlocks = numByteArr.length / (BIT_LENGTH/8);
        byte[] resultByteArr = new byte[BLOCK_SIZE * numBlocks];

        if (VERBOSE_OUTPUT) {
            System.out.println("Decrypting");
            System.out.println("numByteArr Hex: " + bytesToHex(numByteArr));
            System.out.println("Num blocks dec: " + numBlocks);
        }

        for (int i = 0; i < numBlocks; i++) {
            byte[] toNum = Arrays.copyOfRange(numByteArr, i * BIT_LENGTH/8, (i+1) * BIT_LENGTH/8);

            toNum = trimArr(toNum); //todo maybe look into it, doesn't seem needed now
            num = new BigInteger(1, toNum);
            if (VERBOSE_OUTPUT) {
                System.out.println("Dec before s&m: " + num);
                System.out.println("toNum Hex: " + bytesToHex(toNum));
                System.out.println("num.toByteArray() Hex: " + bytesToHex(num.toByteArray()));
            }
            num = square_and_multiply(num, eInv, n);
            if (VERBOSE_OUTPUT) {
                System.out.println("Dec after s&m: " + num);
                System.out.println("num.toByteArray() length: " + num.toByteArray().length);
            }

            byte[] toCopy = num.toByteArray();
            removeSignBit(toCopy);
            if (toCopy.length < BLOCK_SIZE)
                toCopy = Arrays.copyOf(num.toByteArray(), BLOCK_SIZE);
            else if (toCopy.length > BLOCK_SIZE) { // testing, might not need
                System.out.println("ERROR: Resulting block to big");
            }
            System.arraycopy(toCopy, 0, resultByteArr, i*BLOCK_SIZE, BLOCK_SIZE);
        }
        resultByteArr = trimArr(resultByteArr);
        return new BigInteger(1, resultByteArr);
    }

    /*** END ENCRYPTION ***/

    public static BigInteger findSophieGermainPrime() {
        Random r = new Random();
        BigInteger p;
        BigInteger safe;
		
        do {
            p = generatePrime(1024, r);
            safe = p.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }while (!solovayStrassenPrimalityTest(safe, 100, r));
		
        return p;
    }

	// This program can also be used to find a "Sophie Germain Prime", using this main
    public static void mainSG(String[] args) {
        System.out.println(findSophieGermainPrime());
    }
	
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        String primesFile = "primes.txt";
        String publicKeyFile = "public_key.txt";
        String privateKeyFile = "private_key.txt";
        String encryptedMessageFile = "encrypted_message.txt";
        String decryptedMessageFile = "decrypted_message.txt";
        int encDec = -1;
        int loadKeys = -1;
        int fileOrCL = -1;
        VariableLengthRSA theRSA;
        String inputFile;
        String inputMessage;
        String[] inputKeys;
        BigInteger importedN = null;
        BigInteger importedE = null;
        BigInteger importedD = null;
        String encryptedMessage;
        String decryptedMessage;

        System.out.println("Would you like to encrypt/decrypt a message or generate keys? (1: encrypt, 2: decrypt 3: keys)");
        encDec = Integer.parseInt(input.nextLine());
        if (encDec == 1) {
            System.out.println("Would you like to load encryption keys from a file or enter in the terminal? (1: file, 2: terminal)");
            loadKeys = Integer.parseInt(input.nextLine());
            if (loadKeys == 1) {
                System.out.println("Please enter the public key file name (ensure n and e are on the first two lines respectively):");
                inputFile = input.nextLine();
                inputKeys = readFromFile(inputFile).split("\n");
                importedN = new BigInteger(inputKeys[0].trim());
                importedE = new BigInteger(inputKeys[1].trim());
            }
            else {
                System.out.println("Please enter n:");
                String nStr = input.nextLine();
                System.out.println("Please enter e:");
                String eStr = input.nextLine();
                importedN = new BigInteger(nStr);
                importedE = new BigInteger(eStr);
            }
            System.out.println("Would you like to encrypt a message from a file or the terminal? (1: file, 2: terminal)");
            fileOrCL = Integer.parseInt(input.nextLine());
            if (fileOrCL == 1) {
                System.out.println("Please enter the message's file name:");
                inputFile = input.nextLine();
                inputMessage = readFromFile(inputFile);
            }
            else {
                System.out.println("Please enter your message:");
                inputMessage = input.nextLine();
            }
            encryptedMessage = VariableLengthRSA.encrypt(inputMessage, importedN, importedE) + "";
            System.out.println("Encrypted message: " + encryptedMessage);
            System.out.println("Encrypted message stored in: " + encryptedMessageFile);
            writeToFile(encryptedMessageFile, encryptedMessage);
        }
        else if (encDec == 2) {
            System.out.println("Would you like to load the decryption key from a file or enter in the terminal? (1: file, 2: terminal)");
            loadKeys = Integer.parseInt(input.nextLine());
            if (loadKeys == 1) {
                System.out.println("Please enter the private key file name (ensure n and d/eInv) are on the first two lines respectively):");
                inputFile = input.nextLine();
                inputKeys = readFromFile(inputFile).split("\n");
                importedN = new BigInteger(inputKeys[0].trim());
                importedD = new BigInteger(inputKeys[1].trim());
            }
            else {
                System.out.println("Please enter n:");
                String nStr = input.nextLine();
                importedN = new BigInteger(nStr);
                System.out.println("Please enter d (eInv):");
                String dStr = input.nextLine();
                importedD = new BigInteger(dStr);
            }
            System.out.println("Would you like to decrypt a message from a file or the terminal? (1: file, 2: terminal)");
            fileOrCL = Integer.parseInt(input.nextLine());
            if (fileOrCL == 1) {
                System.out.println("Please enter the encrypted message's file name:");
                inputFile = input.nextLine();
                inputMessage = readFromFile(inputFile);
            }
            else {
                System.out.println("Please enter your encrypted message:");
                inputMessage = input.nextLine();
            }
            decryptedMessage = bigIntToStr(decrypt(new BigInteger(inputMessage), importedN, importedD));
            System.out.println("Decrypted message: " + decryptedMessage);
            System.out.println("Decrypted message stored in: " + decryptedMessageFile);
            writeToFile(decryptedMessageFile, decryptedMessage);
        }
        else {
            System.out.println("Generating keys");
            theRSA = new VariableLengthRSA("null", "public_key.txt", "private_key.txt");
            System.out.println("Public keys stored in: " + publicKeyFile);
            System.out.println("Private key stored in: " + privateKeyFile);
        }
    }
}
