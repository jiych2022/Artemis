### Pixelfed

- **Application**: Pixelfed <= v0.11.9

- **Threat Impact**: Sensitive data leakage

- **Code**:

  ```
  class ProfileAliasController {
    public function store(Request $request) {
      $acct = $request->input('acct');
      WebfingerService::lookup($acct);
    }
  }
  
  class WebfingerService {
    public static function lookup($query, $mastodonMode = false)
  	{
  		return (new self)->run($query, $mastodonMode);
  	}
    protected function run($query, $mastodonMode) {
      $parts = explode('@', $query);
          $username = $parts[0];
          $domain = $parts[1];
  		$url = "https://{$domain}/.well-known/webfinger?resource=acct:{$username}@{$domain}";
  		Http::retry(3, 100)->get($url);
    } 
  }
  ```

- **POC**:

  1. Listen on 8888 on server side
  1. When creating profile alias, specify `user@localhost:8888` as the old account 
  1. Receive a request on server side. 
