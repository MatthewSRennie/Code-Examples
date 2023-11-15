Matthew Rennie
Variable Length RSA

- Written in IntelliJ
- This code should run in any Java IDE, just open and run it
- Blocks are of size 214 (can be specified at the top, along with other key variables)
- Ascii text is converted to a number (stored in BigInteger), with the last character of the block as the least-significant byte
- Once encrypted each block will be of size 256 bytes because they are encrypted with a 2048 bit number (2048/8 = 256 bytes)
- When encrypted each block is stored as a BigInteger without a sign bit
