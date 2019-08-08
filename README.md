# custodia-head-content-md5

This is a custodia plugin implementing HEAD requests. The plugin also populates the Content-MD5 header when replying to a HEAD request with the md5sum of the content of the secret.

We use this to check the integrity of or update secrets on local machines without the requirement of downloading the entire secret with a GET request.

## Usage
Clone this repo somewhere and ensure the install directory is on the `PYTHONPATH`. Then add something like the following to `/etc/custodia/custodia.conf`:

```
[/]
handler = head-content-md5.HeadHandler
store = encrypted
```
