## BashOIDCD Documentation

```
# /config/packages/bash_oidcd.yaml
bash_oidcd:
    clients:
        main:
            well_known_url: '%env(OIDCD_WELL_KNOWN_URL)%'
            client_id: '%env(OIDCD_CLIENT_ID)%'
            client_secret: '%env(OIDCD_CLIENT_SECRET)%'
            well_known_cache_time: 3600
            redirect_route: '/login/check'
            site_name: 'sportal.bg'
            # Extra configuration options
            #custom_client_headers: []

        # Add any extra client
        #link: # Will be accessible using $linkOidcdClient
            #well_known_url: '%env(LINK_WELL_KNOWN_URL)%'
            #client_id: '%env(LINK_CLIENT_ID)%'
            #client_secret: '%env(LINK_CLIENT_SECRET)%'
```
