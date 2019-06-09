# cmps122-secure-fileserver

This repository contains the result of my final project for CMPS 122: Computer Security. The goal of the project was to design a multi-threaded, multi-user file server that is secure against attackers. While no specific attacks were specified in the lab spec, the goal is defend against whatever attacks my peers could muster. 

The project was built in phases. In phase 1, we created our initial build for the server. 
In phase 2, we evaluated serveral peers' servers by downloading their binaries and source codes, trying to find security flaws, and seeing if we could successfully compromise the server in any way. Attacks attempted included unauthorized access of files outside the user's designated directory, buffer overflow attacks (regardless of result, such as unauthorized access or crashing the thread), and security against malformed requests. 
In phase 3, we took feedback from phase 2 and tried to secure the server against any vulnerabilities found by our peers.

This repository only contains the final version because I (foolishly) did not develop the project in Git and merely uploaded the result after completion.
