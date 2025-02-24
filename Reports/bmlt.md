### BMLT Meeting Map

- **Application**: bmlt-meeting-map <= 2.5

- **Threat Impact**: Sensitive data leakage

- **Code**: Root server URL is retrieved from POST parameter `root_server` and saved into property array `options`. Then `testRootServer` uses this option as parameter as server host URL and pass into `get` function and finally pass into sink `wp_remote_get`.

  File: `meeting_map.php`

  ```
  public function admin_options_page() {
    ...
    $this->options['root_server'] = $_POST['root_server'];
  }
  
  public function get($url, $cookies = null)
  {
    ...
    return wp_remote_get($url, $args);
  }
  
  public function testRootServer($root_server)
  {
    $results = $this->get("$root_server/client_interface/serverInfo.xml");
  }
  
  $this_connected = $this->testRootServer($this->options['root_server']);
  ```

- **POC**:
  1. Listen on 8080 on server side
  1. Login, test root server with URL `http://localhost:8080`
  1. Receive a request on server side. The full response is also disclosed
