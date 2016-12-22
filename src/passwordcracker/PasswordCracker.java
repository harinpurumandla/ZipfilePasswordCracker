package passwordcracker;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.idyl.winzipaes.AesZipFileDecrypter;
import de.idyl.winzipaes.AesZipFileEncrypter;
import de.idyl.winzipaes.impl.AESDecrypter;
import de.idyl.winzipaes.impl.AESDecrypterBC;
import de.idyl.winzipaes.impl.AESEncrypter;
import de.idyl.winzipaes.impl.AESEncrypterBC;
import de.idyl.winzipaes.impl.ExtZipEntry;

/**
 *
 * @author harin
 */
public class PasswordCracker {

    /*
	function encrypt() used from the starters code with few changes, changed the return type to boolean.
     */

    public static boolean encrypt(String inputFilename, String zipFilename, String password) throws Exception {
        try {
            AESEncrypter encrypter = new AESEncrypterBC();
            AesZipFileEncrypter.zipAndEncrypt(new File(inputFilename), new File(zipFilename), password, encrypter);
            return true; // true on successfull encryption
        } catch (Exception e) {
            return false; // false on unsucessfull encryption 
        }
    }

    /*
	function encrypt() used from the starters code with few changes, changed the return type to boolean.
     */
    public static boolean decrypt(String zipFilename, String outputFilename, String password) throws Exception {
        boolean bool = false;
        try {
            AESDecrypter decrypter = new AESDecrypterBC();

            AesZipFileDecrypter dec = new AesZipFileDecrypter(new File(zipFilename), decrypter);
            ExtZipEntry entry = dec.getEntryList().get(0); // assumes only one
            // item is in the
            // zip file
            dec.extractEntry(entry, new File(outputFilename), password);
            dec.close();
            return true; // true on successfull decryption
        } catch (Exception e) {
            return false; // false on unsuccessfull decryption
        }

    }

    /*
getFileExtension() function return the extension of a file 
     */
    public static String getFileExtension(String path) {
        try {
            File file = new File(path);
            String fileName = file.getName();

            if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0) { //validating wether the string is a file address or not
                //System.out.println(fileName.substring(fileName.lastIndexOf(".") + 1));
                return fileName.substring(fileName.lastIndexOf(".") + 1); // returns the substring after the last '.' in the given string
            } else {
                return "";
            }
        } catch (Exception e) {
            System.out.println("invalid file location");
        }
        return null;
    }

    /* 
	characters() function takes 4-boolean inputs and return the allowed characters to a password
     */
    public static char[] characters(boolean alphabets, boolean upper, boolean number, boolean splchars) {
        String Alphaup = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String Alphalow = "abcdefghijklmnopqrstuvwxyz";
        String num = "0123456789";
        String splchar = "~!@#$%^&*()_+`-={}|[]:;'<>?,.";
        String output = "";
        if (alphabets == true) { // lower - case alphapets allowed
            output = output + Alphalow;
        }
        if (upper == true) { // upper- case alphapets allowed
            output = output + Alphaup;
        }
        if (number == true) { // number allowed
            output = output + num;
        }
        if (splchars == true) { // special characters allowed
            output = output + splchar;
        }
        return output.toCharArray(); // returns character array

    }

    /*
	Bruteforce() function takes password, position,length of the password, allowed character array and file path as input and performes bruteforceattack
	Bruteforce() function is a recursion function.
     */

    public static void Bruteforce(String pass, int pos, int length, char[] fin, String file) throws Exception {
        int[] one = new int[length];
        if (pos < length) // checks if position is greater than the length of the password
        {
            for (char ch : fin) // foreach loop which iterates complete character array
            {
                Bruteforce(pass + ch, pos + 1, length, fin, file); // calling Bruteforce() by incrementing the position by one
            }
        } else { // end condition for recursion -- if position is less than or equal to the length of the password 
            System.out.println(pass);// prints the password
            if (decrypt(file, "test2.txt", pass) == true) { // decrypt the file using decrypt() function 
                System.out.println("password is " + pass); // if decrypt() returns true -- password is returned and system is exited.
                System.exit(0);
            }
        }

    }

    /*splchars()  function takes string as input and return true if these are any special characters and false if there are no special characters */
    public static boolean splchars(String str) {
        Pattern p = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE); //regular expression to check for a special character
        Matcher m = p.matcher(str);// match the expression with string
        return m.find(); //returns the result
    }

    /*
	processDictonary() is a function which takes dictonarypath, decryption file path, length of password and a boolean for special characters 
	and performs dictonary attack
     */

    public static void processDictonary(String path, String str, int length, boolean splchar) {
        try {
            BufferedReader is = new BufferedReader(new FileReader(str)); // reads the dictonary file
            String inputLine;
            while ((inputLine = is.readLine()) != null) { // check if the file contains lines
                if (!inputLine.startsWith("#!comment")) { // removing the comment lines
                    if (!(splchar == false && splchars(inputLine) == true)) {
                        /*checking if password allows special character and 
					also if the line consists of special character and if length of line is less than the password length  --  */
                        try {
                            System.out.println(inputLine);
                            if (decrypt(path, "test2.txt", inputLine)) { // file is decrypted using decrypt function
                                System.out.println("PWD is " + inputLine);
                                System.exit(0); // exited is decryption is successfull
                            }
                        } catch (Exception ex) {

                        }
                    }
                }
            }

            is.close(); // close file reader and buffered reader
            System.out.println("password not found");
            System.exit(0);

        } catch (Exception e) {
            // Sytem.out.println("IOException: " + e);
        }
    }

    /**
     * main class
     */
    public static void main(String[] args) throws Exception {

        Scanner keyboard = new Scanner(System.in); // to take input from keyboard
        while (true) { // to create a infinite loop
            System.out.println("Password Cracker");
            System.out.println("Options");
            System.out.println("----------");
            /* 
		Options
		
		1- Encrypt
		2 - Decrypt
		3 - Dictonary
		4- to exit
		
             */
            System.out.println("1 - Encrypt \n2 - Decrypt \n3- Dictonary \n4-exit \n ----------");
            System.out.print("Enter Your Option: ");
            int option = Integer.parseInt(keyboard.next()); // checking if the option entered is a integer

            if (option == 1) {
                System.out.print("Enter file path(complete path): ");
                String path = keyboard.next(); // enter file which is to be encrypted
                if (getFileExtension(path).equals("txt")) { // checking for file extension and if its txt proceed else go back to stating
                    System.out.println("Enter the Password: ");
                    String pwd = keyboard.next(); // entering password with which file is encrypted
                    if (encrypt(path, "test.zip", pwd)) { // encrypt using encrypt() funciton
                        System.out.println("Encryption Sucessful");
                    } else {
                        System.out.println("Encryption unSucessful");
                    }
                } else {
                    System.out.println("Only Text files. ( Beta Version ;) )");
                }
            } else if (option == 2) {
                char[] arr;
                boolean alpha = false;
                boolean num = false;
                boolean splchars = false;
                System.out.println("------------");
                System.out.println("Decryption");
                System.out.println("------------");
                System.out.println("Enter the Zip file which is to be decrypted: ");
                String filepath;
                filepath = keyboard.next(); // inputting encrypted .zip filepath which is to be cracked
                if (!getFileExtension(filepath).toLowerCase().equals("zip")) { // checking if wether the file inputted is a zip or not 
                    System.out.println("Invalid File location, try again");
                } else {
                    System.out.println("\nAllowed Characters");
                    System.out.print("\nAlphabets (yes/no): ");
                    String view = keyboard.next().toLowerCase(); // yes if the password consists of alphapets
                    if ((view).equals("yes") || (view).equals("y")) {
                        alpha = true;
                    } else {
                        alpha = false;
                    }
                    System.out.print("\nNumbers (yes/no)");

                    view = keyboard.next().toLowerCase();
                    if ((view).equals("yes") || (view).equals("y")) { // yes if password consists of numbers
                        num = true;
                    } else {
                        num = false;
                    }

                    System.out.print("\nSpecial Characters (yes/no)");

                    view = keyboard.next().toLowerCase();
                    if ((view).equals("yes") || (view).equals("y")) { // yes if password consists of special characters
                        splchars = true;
                    } else {
                        splchars = false;
                    }
                    System.out.println("Min Length of Password:");
                    int min = keyboard.nextInt(); // inputting the minimum length of password
                    System.out.println("Max Length of Password:");
                    int max = keyboard.nextInt(); // inputting the maximum length of password
                    arr = characters(alpha, alpha, num, splchars);
                    for (int i = min; i <= max; i++) { // for minimum to maximum running the loop
                        System.out.println("Password tired:");
                        Bruteforce("", 0, i, arr, filepath); // performing bruteforce attack
                    }
                    System.out.println("Password not found");

                }

            } else if (option == 3) {
                boolean splchars = false;
                System.out.println("------------");
                System.out.println("Decryption");
                System.out.println("------------");
                System.out.println("Enter the Zip file which is to be decrypted: ");
                String filepath;
                filepath = keyboard.next();// inputting encrypted .zip filepath which is to be cracked
                if (!getFileExtension(filepath).toLowerCase().equals("zip")) {// checking if wether the file inputted is a zip or not 
                    System.out.println("Invalid File location, try again");
                } else {
                    System.out.println("\nAllowed Characters");
                    System.out.println("\nSpecial Characters (yes/no)");
                    String view = keyboard.next().toLowerCase();
                    if ((view).equals("yes") || (view).equals("y")) { // yes if password consists of special characters
                        splchars = true;
                    } else {
                        splchars = false;
                    }
                    String dic;
                    System.out.println("Enter the dictonary file which is to be decrypted: ");
                    dic = keyboard.next(); // inputting dictionary filepath 
                    if (!getFileExtension(dic).toLowerCase().equals("txt")) { // checking if wether the dictonaryfile is a txt file or not 
                        System.out.println("Invalid File location, try again");
                    } else {
                        System.out.println("Max Length of Password:");
                        int max = keyboard.nextInt();// inputting the maximum length of password

                        processDictonary(filepath, dic, max, splchars); // performing dictonary attack
                    }

                }

            } else if (Integer.parseInt(keyboard.next()) == 4) { // to exit from the execution.
                System.exit(0);
            } else {
                System.out.println("Invalid Option, Try again");
            }
        }
    }

}
