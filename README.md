# Connect to a Glopal Protect VPN using NetworkManager (nmcli)

This application allows to create and connect to a Global Protect VPN connection that requires SAML authentication using `nmcli` (NetworkManager).

Make sure to have installed `openconnect` and `network-manager-openconnect`.

## Usage

First, install the requirements:

```bash
python -m pip install -r requirements.txt
```

Then the script can be used, this is the help message:

```
usage: connect-to-global-protect-using-nmcli [-h] --connection-name CONNECTION_NAME --vpn-portal VPN_PORTAL [--vpn-user-group {portal,gateway}]
                                             [--vpn-os {linux,linux-64,win,mac-intel,android,apple-ios}]

Connect to a Glopal Protect VPN connection that requires SAML authenticaton using nmcli.

options:
  -h, --help            show this help message and exit
  --connection-name CONNECTION_NAME
                        Name for the connection to add with nmcli if it's not already created.
  --vpn-portal VPN_PORTAL, --vpn-gateway VPN_PORTAL
                        Address of the portal/gateway of the Global Protect VPN.
  --vpn-user-group {portal,gateway}
                        Usergroup to pass to openconnect. Defaults to 'portal'
  --vpn-os {linux,linux-64,win,mac-intel,android,apple-ios}
                        OS to pass to Global Protect's Portal.
```

## Example:

```bash
python connect_to_global_protect_using_nmcli.py --conection-name "My GlopalProtect VPN" --vpn-portal "portal.testvpn.com" --vpn-user-group "portal" --vpn-os "linux"
```

The script will automatically check if exists a connection with the name "My GlopalProtect VPN" configured for a VPN with the protocol "gp" (GlopalProtect) and for the portal specified, if the connection exists already then it is used to stablish the connection, if not, the script will automatically create a new connection with the parameters specified and use it to connect to the VPN.

After creating/getting the connection that will be used to connect to the VPN, then the script will open a Selenium browser to perform the SAML authentication and get the necessary prelogin cookie and username to get the vpn secrets to then connect  to the VPN via `nmcli`.
