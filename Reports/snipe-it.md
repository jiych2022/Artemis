### snipe-it

- **Application**: snipe-it<=v5.3.3

- **Threat Impact**: Sensitive data leakage

- **Code**:

  ```
  $idpMetadata = $this->input('saml_idp_metadata');
  
  $action = "parseRemoteXML";
  OneLogin_Saml2_IdPMetadataParser::{$action}($idpMetadata);
  
  public static function parseRemoteXML($url,...) {
  $ch = curl_init($url);
  $xml = curl_exec($ch);
  }
  ```

- **POC**:

  1. Listen on 8080 on server side
  1. In settings, specify `http://localhost:8080` as saml2 XML URL.
  1. Receive a request on server side. 

