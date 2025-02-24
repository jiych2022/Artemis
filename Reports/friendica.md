### Friendica

- **Application**: Friendica <= v2021.01

- **Threat Impact**: Sensitive data leakage

- **Code**: 

  ```
  class Register {
  public static function post() {
    $arr = $_POST;
    Model('User')->create($arr);
  }
  }
  class User {
  public function create($data) {
    $photo = $data['photo'];
    DI::httpRequest()->get($photo);
  }
  }
  ```

- **POC**:

  1. Listen on 8888 on server side
  1. When creating a new user, specify `http://localhost:8888` as photo URL.
  1. Receive a request on server side. 

