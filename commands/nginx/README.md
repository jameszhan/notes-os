
```bash
mkdir ssl
openssl req -x509 -nodes -days 36500 -newkey rsa:2048 -keyout `pwd`/ssl/nginx.key -out `pwd`/ssl/nginx.crt
```

```bash
alias curl="curl -k" 
```

```bash
nginx -t -c `pwd`/sourceforge-proxy.conf

nginx -c `pwd`/sourceforge-proxy.conf

nginx -c `pwd`/sourceforge-proxy.conf -s reload
```

```bash
# export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_CURL_VERBOSE=1
export HOMEBREW_CURLRC="-k"
brew cask install kdiff3 --debug --verbose
```