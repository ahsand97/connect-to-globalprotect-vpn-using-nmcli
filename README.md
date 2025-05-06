# Connect to a Global Protect VPN that requires SAML authentication using NetworkManager and openconnect

This application allows to create and connect to a Global Protect VPN connection that requires SAML authentication using `nmcli` (NetworkManager) and `openconnect`.

Make sure to have installed `openconnect` and `network-manager-openconnect`.

## Usage

First, install the requirements:

```bash
python -m pip install -r requirements.txt
```

Then the script can be used, this is the help message:

```
usage: connect_to_global_protect_vpn_using_nmcli [-h] (--connection-name CONNECTION_NAME | --connection-uuid CONNECTION_UUID) --vpn-portal VPN_PORTAL
                                                 [--vpn-user-groups [VPN_USER_GROUP_GET_URL_SAML [VPN_USER_GROUP_CONNECT_VPN ...]]] [--vpn-os VPN_OS]
                                                 [--openconnect-args [OPENCONNECT_ARGS_GET_URL_SAML [OPENCONNECT_ARGS_CONNECT_VPN ...]]]

Connect to a Global Protect VPN connection that requires SAML authenticaton using NetworkManager (nmcli) and openconnect.

options:
  -h, --help            show this help message and exit
  --connection-name CONNECTION_NAME
                        Name for the connection to add with NetworkManager (nmcli) if it's not already created.
  --connection-uuid CONNECTION_UUID
                        Connection UUID for an already existing connection to use to stablish the VPN connection with NetworkManager.
  --vpn-portal, --vpn-gateway VPN_PORTAL
                        Address of the portal/gateway of the Global Protect VPN.
  --vpn-user-groups [VPN_USER_GROUP_GET_URL_SAML [VPN_USER_GROUP_CONNECT_VPN ...]]
                        Usergroups to pass to openconnect's --usergroup parameter. It can be a single value or 2 values. The first value is used when using openconnect to get the URL to perform the SAML authentication and the
                        second one is used when using openconnect to perform the VPN authentication. If the value for this parameter is only 'gateway' then 'gateway' will be used as the --usergroup parameter to get the URL for SAML
                        authentication and for the VPN authentication the --usergroup parameter will be 'gateway:prelogin-cookie'. If the value for this parameter is only 'portal' then 'portal' will be used as the --usergroup
                        parameter to get the URL for SAML authentication and for the VPN authentication the --usergroup parameter will be 'portal:portal-userauthcookie'.
  --vpn-os VPN_OS       OS to pass to openconnect's --os parameter. Options can be: 'linux', 'linux-64', 'win', 'mac-intel', 'android', 'apple-ios'.
  --openconnect-args [OPENCONNECT_ARGS_GET_URL_SAML [OPENCONNECT_ARGS_CONNECT_VPN ...]]
                        Extra arguments to pass to openconnect. It can be a single value or 2 values, make sure to add quotes to distinguish from the normal arguments of the application. The first value contains the extra
                        openconnect arguments used to get the URL to perform the SAML authentication and the second one contains the extra openconnect arguments used to perform the VPN authentication. Example: --openconnect-args "
                        --extra-arg=value --another-arg=value" "--extra-arg=value"
```

## Example:

```bash
python connect_to_global_protect_vpn_using_nmcli.py --connection-name "Test GP VPN" --vpn-portal "portal.testvpn.com" --vpn-user-groups "portal" --vpn-os "linux"
```

The script will automatically check if exists a connection with the name "Test GP VPN" configured for a VPN with the protocol "gp" (GlobalProtect) and for the portal specified, if the connection exists already then it is used to establish the connection, if not, the script will automatically create a new connection with the parameters specified and use it to connect to the VPN.

After creating/getting the connection that will be used to connect to the VPN, then the script will open a Selenium browser to perform the SAML authentication and get the necessary prelogin cookie and username to get the vpn secrets to then connect  to the VPN via `nmcli`.

Example of output of an existing connection successfully connected:

![image](https://github.com/ahsand97/connect-to-globalprotect-vpn-using-nmcli/assets/32344641/33d91dc5-e7b8-4f60-b318-32fc2b8bee43)
![Screenshot_20231123_125230](https://github.com/ahsand97/connect-to-globalprotect-using-nmcli/assets/32344641/956e3bec-21b7-40e9-85c4-d4d968de2672)

To delete the cache and do the SAML authentication again, the folder `~/.config/connect_to_global_protect_vpn_using_nmcli` can be removed.
