Artemis requires
1. PHP8.1 and php-ast extension.
   To install php-ast extension, follow the instruction at https://github.com/nikic/php-ast
2. Java21
3. Joern (https://github.com/joernio/joern)
4. OSTRICH (https://github.com/uuverifiers/ostrich)

To run Artemis, first set openai api in environment variable:

 export OPENAI_API_KEY=<your-openai-api-key>

Then adjust config.properties

Finally run command:

 php main.php <absolute-path-to-source> <absolute=path-to-libraries-and-tests>


For example, to run the demo application, CVE-2022-0768:

 php main.php "/abs/path/to/applications/alltube" "/abs/path/to/applications/alltube/vendor;/abs/path/to/applications/alltube/tests"


To generate exploit, setup the target application in Docker.
After that, run a Python local server inside the container, listen on localhost 8888, and export the access log to a folder mapped to host.
For example, use command:

 nohup python3 -u -m http.server 8888 > /log/log-app1.txt 
 
in container, map /log to a folder outside of the container, say `/home/user/logs`, then log will be generated in /home/user/logs/log-app1.txt 

Open constructExploit/config.php, edit the variables to actual values. All paths need to be absolute path.
Open constructExploit/setup.php, properly login through code or through cookie. This script will be run before the exploit for any authentication.
If CSRF tokens are required, also add it through the requests.before_request hook like in the comment.
Copy the input into $taintResult in config.php
Then run command:

 php exp.php

The exploit will be generated in spec.json and automatically validated.
 
 
