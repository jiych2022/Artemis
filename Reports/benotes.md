### Benotes

- **Application**: benotes <= 2.8.2

- **Threat Impact**:  Sensitive data leakage

- **Code**:

  File: `app/Http/Controllers/PostController.php`

  ```
  class PostController {
  public function getUrlInfo($request)
      {
        $this->service->getInfo($request->url()));
      }
  }
  
  class Request {
    private $data = $_POST + $_GET;
    public function __call($method, $args) {
      return $this->data[$method];
    }
  }
   class PostService {
        public function getInfo($url) {
        	curl_setopt($ch, CURLOPT_URL, $url);
        }
   }
  ```

- **POC**:

  1. Listen on 8888 on server side
  1. Use http://127.0.0.1:8888 for link preview
  1. Receive a request on server side. The partial response is also disclosed
