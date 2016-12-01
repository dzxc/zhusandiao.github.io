```perl
server {
    listen 80;
    listen [::]:80 default_server;
    server_name git.zhusandiao.com; # 修改域名
    server_tokens off;
    location /generate_204 { return 204; }
    # Discourage deep links by using a permanent redirect to home page of HTTPS site
    return 301 https://$host;
    # Alternatively, redirect all HTTP links to the matching HTTPS page
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    # listen [::]:443 ssl http2 default_server;
    server_name git.zhusandiao.com; # 修改域名
    server_tokens off;
    location /generate_204 { return 204; }

    # ssl on;
    ################
    # SSL 配置
    ################
    ssl_certificate /etc/letsencrypt/live/git.zhusandiao.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/git.zhusandiao.com/privkey.pem;
    ################
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    # ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ciphers "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5:!MEDIUM:!LOW";
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    # Disable preloading HSTS for now.  You can use the commented out header line that includes
    # the "preload" directive if you understand the implications.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    # add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    # ssl_dhparam /etc/nginx/certs/dhparam.pem;
    ################
    # SSL END
    ################
    add_header 'Access-Control-Allow-Origin' *;
    add_header 'Access-Control-Allow-Methods' 'GET,POST,OPTIONS';
    location / {
        proxy_pass http://192.243.116.118:4000; # 修改为你的 IP:port
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}



server {
    listen  80;
    server_name wall.zhusandiao.com;
    rewrite     ^   https://$host$request_uri? permanent;
    location / {
        root /home/www/wall;
            index index.html index.htm index.php;
        }
    #error_page 404 /404.html;
    # include enable-php.conf;       
        location /.well-known {
            alias /var/www/wall.zhusandiao.com/.well-known;
        }
    location ~/\ {
        deny all;
    }
    access_log /home/wwwroot/wall/wall.access.log;
        error_log /home/wwwroot/wall/wall.error.log;
}
server {
    listen 443 ssl;
    server_name wall.zhusandiao.com;
    ssl_certificate /etc/letsencrypt/live/wall.zhusandiao.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wall.zhusandiao.com/privkey.pem;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=31536000";
    location /.well-known {
        alias /var/www/wall.zhusandiao.com/.well-known;
    }
    location / {
    root /home/www/wall;
        index index.html index.htm index.php;
    }
}
```