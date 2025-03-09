curl  tool
------
./curl.sh -d "https://www.example.com" -p "/home/anom/payloads/PayloadsAllTheThings/SQL Injection/Intruder/SQLi_Polyglots.txt" -r "50k" -t 3

Explanation:
-d: Your target URL (required)
-p: Custom payload file (optional, defaults to payloads.txt)
-u: Custom User-Agent (optional)
-x: Proxy URL (optional)
-r: Rate limit for requests (optional, defaults to 100k)
-t: Delay between requests in seconds (optional, defaults to 2)



xss
---
./xss 
