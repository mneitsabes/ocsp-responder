
This server allows OCSP requests to be answered based on the CRL file.

# Installation
    
 * Create a dedicated directory. For this example, we'll use `/opt/ocsp-responder`
 * Create a venv with `python3 -m venv venv`
 * Generate an certificate/private key pair for the OCSP signing (`extendedKeyUsage` must be `OCSPSigning`)
 * Put the OCSP signing certificate and private key in `/opt/ocsp-responder`
 * Activate the venv and install the requirements with `source /opt/ocsp-responder/venv/bin/activate && pip3 install -r requirements.txt`

You can run the responder directly with : `./ocsp_responder.py --port 8888 --crl crl.pem --ocsp-cert ocsp.pem --ocsp-key ocsp.key --ca ca.pem`

It's recommended to serve it through nginx.

# nginx configuration

The nginx configuration to serve OCSP behind nginx with caching :

    server {
        listen 80;
        server_name ocsp.pki.example.com;

        client_max_body_size 1k;      # OCSP responses are small and frequent
        keepalive_timeout 5s;         # and short

        access_log /var/log/nginx/ocsp_access.log combined;
        error_log /var/log/nginx/ocsp_error.log warn;

        location / {
            proxy_pass http://127.0.0.1:8888;
            proxy_http_version 1.1;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;

            proxy_connect_timeout 1s;
            proxy_send_timeout    1s;
            proxy_read_timeout    1s;

            # OCSP responses caching
            #proxy_cache ocsp_cache;
            #proxy_cache_key "$request_uri";
            #proxy_cache_valid 200 1h;      # cache good response
            #proxy_cache_valid 400 1m;      # cache temporary errors
            #proxy_cache_use_stale error timeout invalid_header updating;

            # Very important for OCSP
            add_header Cache-Control "max-age=43200, public";
        }
    }


# Test

Run the following command to test the responder :

    openssl ocsp -issuer intermediate_ca.pem -cert server.pem -url http://127.0.0.1:8888/ocsp -nonce -VAfile root_ca.pem -text

You should see :

    Response verify OK
    server.pem: good

or 

    Response verify OK
    server.pem: revoked