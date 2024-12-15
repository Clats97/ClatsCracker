# Usage Guide
1. Run the Tool: Start from your command line, IDE or python file directly
2. Choose Resource Usage (Threads):

- Option 1: Low (1 thread) 
- Option 2: Medium (4 threads) 
- Option 3: High (8 threads) 
- Option 4: Custom (1–1000 threads) 
  
>[!NOTE]
> Begin with Low or Medium if you’re new. You can adjust resources later if needed. 

3. Main Menu:  
-  Option 1: Crack Password 
-  Option 2: Exit 
  
4. Select Option 1 to proceed. 5
5. . Hash Detection: 
Either let the tool auto-detect the hash type or specify the algorithm if prompted. 
6. Enter the Hash Value: Paste or type the hash. If invalid, you’ll be asked to re-enter. 
7. Choose the Cracking Method:  
- **Dictionary-Based:** Provide dictionary file paths. The tool deduplicates and tests each password. 
- **Brute Force:** Specify password length. The tool tries all character combinations of that length. 
8. Run the Cracking Process & Observe real-time metrics (ETA, APS). If a match is found, it’s displayed; if not, you’ll be informed. 

9.  **Interruption & Adjustment:** If you need to stop or adjust threads mid-process, do so via ctrl+c. The tool handles interruptions and dynamic changes without losing state and will attempt to exit gracefully.  
10.   **Timing & Feedback:** After completion, the tool reports total runtime and logs the session, aiding in analysis and performance optimization. 


## Example Usage 
###  Dictionary Attack (MD5):  
1. Select resource usage. 
2. Choose “Crack Password.” 
3. Allow auto-detect or specify md5.
4. Enter the MD5 hash.
5. Select dictionary-based attack, provide dictionary file(s). The tool runs until it finds a match or exhausts options. 


### Brute Force Attack (SHA1):  
1. Select resource usage. 
2. Choose “Crack Password.” 
3. Allow auto-detect or specify sha1.
4. Enter the SHA1 hash.
5. Choose brute force, specify length (e.g., 4). The tool attempts all 4-character passwords, reporting APS and ETA. 
