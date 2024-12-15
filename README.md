# ClatsCracker v1.0.1
ClatsCracker is a Python-based password cracking tool designed to help security professionals, penetration testers, and hobbiests test and strengthen their password security.

>[!IMPORTANT]
>**Legal & Ethical Disclaimer**
>
>This tool is for educational authorized security testing only. Always act lawfully and ethically. Compliance with all applicable laws and regulations is solely your responsibility. 
## What the Tool Does 
- **Hash Cracking**
  
Given a password hash, ClatsCracker attempts multiple passwords—either from dictionary files or via brute force. If a match is found, the recovered password is displayed. 

-  **Algorithms Supported**

**Unsalted:** MD5, SHA1, SHA256, SHA512, SHA3-256, Scrypt 

**Salted:** Bcrypt, Argon2id Supporting eight popular hashing algorithms,

- **Cracking Methods:** 

**Dictionary-Based Attacks:** Quickly test large lists of known or common passwords, removing 
duplicates for efficiency. 

**Brute Force Attacks:** Systematically try every possible password of a given length and 
character set, ideal for unknown or very strong passwords.

>[!NOTE]
> **High performance wordlist dictionary file available**
>
> A 160GB+ (approx 19.5bn passwords) wordlist dictionary file is available by request, email **skyline92x@pm.me** with a request for this file and you will be given a single use password protected link to download the file via MEGA, due to bandwidth constraints it may not be possible to provide this link immediately but your request will be fulfilled once bandwidth resets monthly. 

## **Highlights**

- **Multi-Algorithm support:** Crack MD5, SHA1, SHA256, SHA512, SHA3-256, Scrypt, Bcrypt, and Argon2id hashes, all within a single tool.

- **Flexible Attack methods:** Choose between dictionary-based or brute-force attacks, enabling both quick tests against known password lists and exhaustive searches for complex passwords.

- **Scalable resource usage:** Adjust the number of threads used at your discretion to optimize crack speed. 3 presets exist, low (1), medium (4) and high (8). 

- **Hash auto detection** Automatically identify the type of hash provided, streamlining the workflow and eliminating guesswork 
  
- **Event logging:** All events are logged into a file, crashes and user exits do not impact the integrity of the log as it is written as the events happen. 

- **Real time metrics:** Estimated Time of Arrival (ETA) and Attempts Per Second (APS) metrics, giving users insight into current performance and how long the cracking process might take. 

- **Verification of Salted Hashes:** Salted hashes like Bcrypt and Argon2id require precise handling. Many tools fail by rehashing passwords with new salts, ClatsCracker uses:

• `bcrypt.checkpw()` - for Bcrypt 

• `PasswordHasher.verify()` - for Argon2id 

This ensures proper validation of the original salts and parameters, increasing the likelihood of successfully cracking more complex hashes.



## Usage Requirements 
- **Python 3**
- Libraries:  
  
**Built-in:** `hashlib`, `itertools`, `string`, `sys`, `os`, `time`, `threading`, `concurrent.futures` 

**External:** `bcrypt`, `argon2-cffi`

>[!NOTE]
> The usage guide & example usages can be found [here](usage.md)






## FAQ 

### Q: Why is it slow?
- A: Some algorithms are designed to be slow. Increase threads, use more powerful hardware, or accept that certain algorithms resist quick cracking with limited hardware resources.

### Q: Why is my hash is not recognized?
- Ensure the hash is correctly formatted or let the tool auto-detect the type. 

### Q: Can I add more algorithms? 
- Yes, contributions are welcomed openly and much appreciated, please ensure your contribution works and provide test evidence if you do wish to make a pull request to add more algorithms to the supported list



## Limitations & Future Considerations 
- Cracking speed depends on hash complexity and system resources. 
- Algorithms like Argon2id and Scrypt are intentionally slow, resisting brute force attempts. 
- Ongoing changes in hashing standards may require future tool modifications. 

## Photos of the tool
![screenshot cracker](https://github.com/user-attachments/assets/ae714282-cbf4-4f7c-a965-581f6c420208)
![screenshot2](https://github.com/user-attachments/assets/2ee5eb43-bcae-4fea-a3f7-47101eb1d6c3)
![screenshot3](https://github.com/user-attachments/assets/f60ba58e-da49-4d49-80a3-50e142889b0c)
![screenshotcracker2](https://github.com/user-attachments/assets/0956ae56-8457-4b8f-ac57-59dc10f54662)



## Support 

For any issues with the tool please submit a github issue explaining in detail the fault you are experiencing, the steps leading up to it, the operating system you are using as well as screenshots if possible. 

developer email for direct suppport: **skyline92x@pm.me**