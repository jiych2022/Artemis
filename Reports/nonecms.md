### Nonecms

- **Application**: nonecms <= v1.3.0

- **Threat Impact**: Sensitive data leakage

- **Code**: 

  ```
  function do_click() {
    ...
    $url   = $_POST['url'];
    ...
    wp_remote_post( $url,...);
  }
  ```

- **POC**:

  1. Listen on 8888 on server side
  1. When uploading images, use `http://localhost:8888` as image URL.
  1. Receive a request on server side. 



