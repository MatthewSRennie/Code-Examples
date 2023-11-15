// Created by Matthew Rennie
// Vigenere Decoder
// vigenere_decoder.cpp

// You will be prompted to enter the encrypted text after running this program
// You may optionally pass in a single text file as an argument containing the encrypted text

// This program will decode a Vigenere cipher
// A Vigenere cipher encodes a string using a given key, by shifting the each letter according to the key
// For example, the string 'aaaaa' encoded with the string 'abc', would result in an encoded string 'abcab'
// This method of decryption will only work with English text
// The program first finds the key length using an 'Index of Coincidence' test, then performs a frequency
//   analysis to find the key
// For more information on the Vigenere cipher, or if you would like to encrypt a string to test,
//   visit: https://www.dcode.fr/vigenere-cipher

// This program could have been written more concisely, some things are repeated, but I wanted to write
//   each part as a separate function for clarity
// All the methods expect the string to be lowercase except when noted otherwise

#include <iostream>
#include <cstring>
#include <bits/stdc++.h> 

#define IC_ENGLISH 0.0667

bool verbose_output;

double calculate_ic(std::string str) {
	int count[26];
	memset(count, 0, sizeof(int)*26);
	
	for (int i = 0; i < str.length(); i++) {
		count[str[i]-'a']++;
	}
	
	double icsum = 0;
	for (int i = 0; i < 26; i++) {
		double temp = count[i] * (count[i] - 1);
		icsum += temp;
	}
	icsum  /= str.length()*(str.length() - 1);
	
	return icsum;
}

int find_key_length(std::string enc_text) {
	const double IC_THRESHOLD = 0.01; // how close the calculated variable "ic" needs to be to the IC of English
	double ic;
	int key_length = 0;
	
	do {
		ic = 0;
		key_length++;
		std::vector<std::string> split_strings(key_length);
		for (int i = 0; i < enc_text.length(); i++) {
			split_strings[i%key_length] += enc_text[i];
		}
		for (int i = 0; i < key_length; i++) {
			ic += calculate_ic(split_strings[i]);
		}
		ic /= key_length;
		
		if (verbose_output)
			std::cout << "IC for key length " << key_length << " is: " << ic << std::endl;
		
	} while(ic + IC_THRESHOLD < IC_ENGLISH && key_length < enc_text.length());
	
	if (verbose_output) {
		std::cout << "Found the key length: " << key_length << std::endl;
	}
	
	return key_length;
}

double calculate_mutual_ic(std::string str) {
	const double ENGLISH_FREQ_DIST[] = {0.082,0.015,0.028,0.042,0.127,0.022,0.020,0.061,0.070,0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,0.063,0.091,0.028,0.010,0.023,0.001,0.020,0.001};
	int count[26];
	memset(count, 0, sizeof(int)*26);
	
	for (int i = 0; i < str.length(); i++) {
		count[str[i]-'a']++;
	}
	
	double frequency[26];
	double mic = 0;
	for (int i = 0; i < 26; i++) {
		mic += ENGLISH_FREQ_DIST[i] * (count[i] / (double) str.length());
	}
	
	return mic;
}

// Shifts left (-)
std::string shift_string(std::string str, int shift) {
	std::string result;
	for (int i = 0; i < str.length(); i++) {
		int temp = (int) (str[i] - 'a');
		temp += 26 - shift;
		temp %= 26;
		result += (char) (temp + 'a');
	}
	return result;
}

// str is lowercase, returns key upppercase
std::string find_key(std::string str, int key_length) {
	std::vector<std::string> split_strings(key_length);
	double mic_max;
	int key[key_length];
	for (int i = 0; i < str.length(); i++) {
		split_strings[i%key_length] += str[i];
	}
	for (int i = 0; i < key_length; i++) {
		if (verbose_output) {
			std::cout << "Key " << i << ":" << std::endl;
		}
		mic_max = 0;
		for (int j = 0; j < 26; j++) {
			std::string shifted_str = shift_string(split_strings[i], j);
			double mic_temp = calculate_mutual_ic(shifted_str);
			if (mic_temp > mic_max) {
				mic_max = mic_temp;
				key[i] = j;
			}
			if (verbose_output) {
				std::cout << "  Shift " << j << ": " << mic_temp << std::endl;
			}
		}
	}
	
	std::string result = "";
	for (int i = 0; i < key_length; i++) {
		result += (char) (key[i] + 'A');
	}
	if (verbose_output)
		std::cout << "Found the key: " << result << std::endl;
	
	return result;
}

// Expects str lowercase and key uppercase
std::string decode_with_key(std::string str, std::string key) {
	std::string result;
	for (int i = 0; i < str.length(); i++) {
		int temp_str = (int) (str[i] - 'a');
		int temp_key = (int) (key[i%key.length()] - 'A');
		temp_str += 26 - temp_key;
		temp_str %= 26;
		result += (char) (temp_str + 'a');
	}
	return result;
}


int main(int argc, char** argv) {
	verbose_output = true;
	std::string input;
	std::ifstream fileIn;
	
	if (argc == 2) {
		fileIn.open(argv[1]);
	} else if (argc > 2) {
		std::cout << "Too many arguments" << std::endl;
		return 1;
	}
	
	if (fileIn.is_open()) { // If no file to read in
		while (!fileIn.eof()) {
			char c = fileIn.get();
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				input += c;
			}
		}
		fileIn.close();
	}
	else {
		std::cout << "Please enter the text to decode:\n";
		std::cin >> input;
	}
	
	if (verbose_output) {
		std::cout << "Encoded string:\n" << input << std::endl;
	}
	
	transform(input.begin(), input.end(), input.begin(), ::tolower); // make the text lowercase
	
	int key_length = find_key_length(input);
	std::string the_key = find_key(input, key_length);
	std::cout << "Decoded string:\n";
	std::cout << decode_with_key(input, the_key) << std::endl;
	
	return 0;
}