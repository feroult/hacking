# shellcode

shellcode 1 - (Nov 25, 1998)
 
this proggie generates a binary execve code for any commands 
with any arguments. it shows the asm and hex  code of execve 
wanted. both outputs asm and hex code can be executed on the 
stack. for example, you can use it when you want to  exploit
a buffer overrun situation on linux.
 
any comments and sugestions to jamez@sekure.org

thanks for all people from sekure sdi(www.sekure.org)

# backdoor

Linux backdoor using ICMP technique

Coded by jamez - jamez#sekure.org (Sep 13, 1998)

_Reverse shell functionality added by Mihai Sbirneciu - mihai.sbirneciu#gmail.com (Nov 17, 2014)
Special thanks to Alexander G. for bringing this gem to my attention._

You must run the backdoor as root to be able to sniff ICMP:    
```bash
./backdoor packet_size
                |
                `-> ICMP payload size required to activate the backdoor 
```
To activate the backdoor: `ping host -s packet_size`
  
http://www.sekure.org

http://speknet.tumblr.com/
