# Cabbage
Wrapper around the Koala API for Rust.

## Implemented APIs
- OAuth2

## Usage
To use this library, you need to register your application in Koala as an OAuth2 client.
After that, you can start using the library.

```rust
async fn main() {
    let client = KoalaApi::new("https://koala.svsticky.nl".to_string()).unwrap();    
    
    // For example, the user logged in to your application
    let oauth_api = client.oauth_api(ClientConfig::new("my_client_id", "my_client_secret", "https://myapp.svsticky.nl/login"));
    
    let tokens = oauth_api.exchange_login_code(logincode).await.unwrap();
}
```

## License
MIT or Apache-2.0, at your option