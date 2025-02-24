### CommentLuv

- **Application**: CommentLuv <= 3.0.4 

- **Threat Impact**: Sensitive data leakage

- **Code**: 

  ```
  function fetch_feed() {
    $url      = esc_url( $_POST['url'] );
    ...
    new $rss->file_class( $url, $rss->timeout, 5, null, $rss->useragent, $rss->force_fsockopen );
  }
  
  class SimpleCluvPie_File
  {
    public function __construct($url, $timeout = 10, $redirects = 5, $headers = null, $useragent = null, $force_fsockopen = false)   {
      $fp = curl_init();
  	curl_setopt($fp, CURLOPT_URL, $url);
  	curl_exec($fp);
    }
  }
  ```

- **POC**:

  1. Listen on 8080 on server side
  1. When specifying RSS, use `http://localhost:8888` as url.
  1. Receive a request on server side. 

