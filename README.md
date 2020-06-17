# secure-fileserver

This repository contains the result of my final project for my Computer Security class. The goal of the project was to design a multi-threaded, multi-user file server that is secure against attackers. While no specific attacks were specified in the lab spec, the goal is defend against whatever attacks my peers could muster. 

The project was built in phases. In phase 1, we created our initial build for the server. 
In phase 2, we evaluated serveral peers' servers by downloading their binaries and source codes, trying to find security flaws, and seeing if we could successfully compromise the server in any way. Attacks attempted included unauthorized access of files outside the user's designated directory, buffer overflow attacks (regardless of result, such as unauthorized access or crashing the thread), and security against malformed requests. 
In phase 3, we took feedback from phase 2 and tried to secure the server against any vulnerabilities found by our peers.

This repository only contains the final version because I (foolishly) did not develop the project in Git and merely uploaded the result after completion.



The lab journal I wrote for the course is included below:

I implemented the assignment by creating two primary functions, `httpGet` and `httpPost`,
which are called by `httpRequest` depending on the method parsed from the request.  
`httpPost` was originally implemented to do the reverse of `httpGet`. I struggled for a long time
with parsing `httpPost` requests until I realized that the difficulty came from using HTML form type
posts (using `curl`’s `-F` flag), and when I switched to using a raw upload (using `curl`’s
`--data-binary` flag) it became much more manageable.
I mistakenly thought that the user shouldn’t have to specify their own subdirectory, so my
code automatically writes to their subdirectory regardless of whether or not they included it in
the filepath (and if they did include their directory in the filepath, it is removed).
Implementing cookies was fairly straightforward except in how it messed with the
existing functions. Because cookies were not part of the original implementation, I just added a
helper function verifyCookie to check if the cookie was valid and called the function from within
`httpGet` and `httpPost`. For generating cookies I implemented a login function to be called from
within `httpPost` if the destination endpoint is `/login` that checks if the username and password
provided match those in a predefined `users` file. If so, a random cookie is generated. I heard
from a classmate that seeding the `rand()` function with just `time(NULL)` is a terrible idea because
it can reasonably be forged, I seeded the function with `time(NULL) * getpid()` since process IDs
are privileged information that should be impossible for an attacker to know, especially since it is
the PID of the _child_ process of the `fork()`, which should be nigh-impossible to guess.
To prevent users from illegally accessing other users’ directories, I manually scan
through the input filepath and remove all instances of `../` (without any kind of warning provided
to the user).
For evaluating other students’ submissions in Phase II, the first thing I checked beyond
basic functionality was if I could access other users’ directories by including `../` in the filepath
(by utilizing curl’s `--path-as-is` flag). I also checked if invalid requests (e.g. just sending “foo” as
the request) causes the child process to crash. Lastly, I tried buffer overflow attacks of varying 
lengths to see if it could affect or break the server in any way.

In Phase III, I replaced the `system()` call I had, which could potentially be an attack vector that
my peers missed in Phase II, with the `getcwd()` and `mkdir()` C functions 
(learned from reading submissions in Phase II). I believe buffer overflow attacks
should be impossible because _every_ time I copy or concatenate user input, I bound the function
by using `strncpy()` and `strncat()` and making sure that it copies no further than the end of the
destination array.

Pages referenced:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/​ used various subpages for info
and examples on HTTP header formats

https://stackoverflow.com/questions/5457608/how-to-remove-the-character-at-a-given-index-from-a-string-in-c​ 
gave me the idea for how to scrub any `../` from the input filename

https://en.wikipedia.org/wiki/List_of_HTTP_status_codes​ for reference on correct response
codes

https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies​ for reference on cookie format

https://superuser.com/questions/1158551/getting-the-parent-directory-with-curl​ to verify that
one can indeed use relative paths to reach a parent directory

https://www.tutorialspoint.com/c_standard_library/​ various subpages for C function reference
