# Artemis: Toward Accurate Detection of Server-Side Request Forgeries through LLM-Assisted Inter-Procedural Path-Sensitive Taint Analysis

This repository contains the source code of Artemis and new SSRF reports from the paper: `Artemis: Toward Accurate Detection of Server-Side Request Forgeries through LLM-Assisted Inter-Procedural Path-Sensitive Taint Analysis` by  Yuchen Ji, Ting Dai, Zhichao Zhou, Yutian Tang and Jingzhu He. 

## Setup Environment

Artemis requires:

1. PHP>=7.4 and php-ast extension. To install php-ast extension, follow the instruction at https://github.com/nikic/php-ast
2. Java21
3. Joern (https://github.com/joernio/joern)
4. OSTRICH (https://github.com/uuverifiers/ostrich)

## Run

To run Artemis, first set openai api in environment variable:

` export OPENAI_API_KEY=<your-openai-api-key>`

Then adjust `config.properties` for various path to tools

Finally run command:

 `php main.php <absolute-path-to-source> <absolute=path-to-libraries-and-tests>`

To generate exploit, setup the target application in Docker.
After that, run a Python local server inside the container, listen on `localhost:8888`, and export the access log to a folder mapped to host.
For example, use command:

 `nohup python3 -u -m http.server 8888 > /log/log-app1.txt` 

in container, map `/log` to a folder outside of the container, say `/home/user/logs`, then log will be generated in `/home/user/logs/log-app1.txt` 

Open `constructExploit/config.php`, edit the variables to actual values. All paths need to be absolute path.
Open `constructExploit/setup.php`, properly login through code or through cookie. This script will be run before the exploit for any authentication.
If CSRF tokens are required, also add it through the requests.before_request hook like in the comment.
Copy the input into `$taintResult` in `config.php`
Then run command:

` php exp.php`

The exploit will be generated in `spec.json` and automatically validated.

## Citation
If you use Artemis in your research, please cite the paper as follows.
```
@article{ji2025artemis,
  title={Artemis: Toward Accurate Detection of Server-Side Request Forgeries through LLM-Assisted Inter-procedural Path-Sensitive Taint Analysis},
  author={Yuchen Ji and Ting Dai and Zhichao Zhou and Yutian Tang and Jingzhu He},
  journal={Proceedings of the ACM on Programming Languages},
  volume={9},
  number={OOPSLA1},
  year={2025},
  publisher={ACM New York, NY, USA}
}
```
