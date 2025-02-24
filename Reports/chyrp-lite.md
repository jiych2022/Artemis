### chyrp-lite

- **Application**: chyrp-lite <=2023.02

- **Threat Impact**: Sensitive data leakage

- **Code**:

  ```
  public function admin_import_tumblr(){
    $url = $_POST['tumblr_url']."/api/read?num=50";
    get_remote($url);
  }
  ```
  
  File: `includes/helpers.php`

  ```
  function get_remote($url, $redirects = 0, $timeout = 10, $headers = false) {
    extract(parse_url(add_scheme($url)), EXTR_SKIP);
    $connect = @fsockopen($prefix.$host, $port, $errno, $errstr, $timeout);
  }
  ```
  
- **POC**:
  
  1. Listen on 8080 on server side
  1. When importing from tumblr, use `url=http://localhost:8080`
  1. Receive a request on server side. 
