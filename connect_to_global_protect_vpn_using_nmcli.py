import subprocess
import traceback
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import IO, NamedTuple, Optional, cast
from xml.etree import ElementTree as ET

from selenium import webdriver
from selenium.common.exceptions import NoSuchWindowException, TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.support.wait import WebDriverWait


def create_connection(connection_name: str, vpn_portal: str, vpn_os: Optional[str]) -> Optional[str]:
    """Check if connection exists with `nmcli` considering the connection protocol (it should be gp), name and vpn portal specified via CLI"""
    uuid_of_desired_connection: Optional[str] = None
    connections: list[str] = subprocess.check_output(
        args=["bash", "-c", "nmcli --terse --fields NAME,UUID connection"], text=True
    ).splitlines()
    for conn in connections:
        if not len(conn):
            continue
        if conn.split(sep=":")[0] == connection_name:
            # There's already a connection with the same name, we check if its vpn configuration (protocol and gateway)
            # to see if the connection already exists and take its uuid to connect to it
            try:
                vpn_info: list[str] = (
                    subprocess.check_output(
                        args=[
                            "bash",
                            "-c",
                            f"nmcli --terse connection show {conn.split(sep=':')[1]} | grep 'vpn.data'",
                        ],
                        text=True,
                    )
                    .split(sep=":", maxsplit=1)[1]
                    .split(sep=",")
                )
                vpn_info_dict: dict[str, str] = {}
                for info in vpn_info:
                    key: str = info.split(sep="=", maxsplit=1)[0].strip()
                    value: str = info.split(sep="=", maxsplit=1)[1].strip()
                    vpn_info_dict[key] = value
                if not {"gateway", "protocol"} <= set(vpn_info_dict):
                    continue
                if vpn_info_dict["gateway"] == vpn_portal and vpn_info_dict["protocol"] == "gp":
                    uuid_of_desired_connection = conn.split(sep=":")[1]
                    print(
                        f'\nVPN connection "{connection_name}" with uuid "{uuid_of_desired_connection}", vpn protocol '
                        f'"gp" and vpn portal "{vpn_portal}" found, using it to connect with nmcli...\n'
                    )
                    break
            except:
                pass
    if uuid_of_desired_connection is None:  # Create connection
        try:
            vpn_data: dict[str, str] = {
                "authtype": "password",
                "autoconnect-flags": "0",
                "certsigs-flags": "0",
                "cookie-flags": "2",
                "disable_udp": "no",
                "enable_csd_trojan": "no",
                "gateway": vpn_portal,
                "gateway-flags": "2",
                "gwcert-flags": "2",
                "lasthost-flags": "0",
                "pem_passphrase_fsid": "no",
                "prevent_invalid_cert": "no",
                "protocol": "gp",
                "resolve-flags": "2",
                "stoken_source": "disabled",
                "xmlconfig-flags": "0",
            }
            if vpn_os is not None:
                vpn_data["reported_os"] = vpn_os
            msg_creating_connection: str = f'Creating VPN connection with name "{connection_name}", vpn protocol "gp"'
            msg_creating_connection += f'{"," if vpn_os is not None else " and"} vpn gateway "{vpn_portal}"'
            msg_creating_connection += f' and reported os "{vpn_os}"' if vpn_os is not None else ""
            msg_creating_connection += "..."
            print(f"\n{msg_creating_connection}")
            command_to_create_connection: str = (
                f"nmcli connection add con-name '{connection_name}' type vpn vpn-type openconnect "
                f"vpn.data {','.join(f'{k}={v}' for k,v in vpn_data.items())}"
            )
            print(f'Running command: "{command_to_create_connection}"\n')
            result_of_created_connection: str = subprocess.check_output(
                args=["bash", "-c", f"LANG=en {command_to_create_connection}"], text=True
            ).replace("\n", "")
            uuid_of_desired_connection = result_of_created_connection.split(sep="(")[1].split(sep=")")[0]
            print(
                f'VPN connection "{connection_name}" successfully created, uuid of new connection: "{uuid_of_desired_connection}"\n'
            )
        except Exception as e:
            print(f'An error occurred creating connection "{connection_name}", exception: {e}')
            traceback.print_tb(tb=e.__traceback__)
    return uuid_of_desired_connection


def connection_is_active(connection_name: str, connection_uuid: str) -> bool:
    """Check if the connection with `connection_name` and `connection_uuid` is already connected"""
    active_connections: list[str] = subprocess.check_output(
        args=["bash", "-c", "nmcli --terse --fields UUID connection show --active"], text=True
    ).splitlines()
    for active_connection in active_connections:
        if active_connection == connection_uuid:
            print(f'The connection "{connection_name}" with uuid "{connection_uuid}" is already active...')
            return True
    return False


def connect_to_vpn_using_nmcli(
    vpn_portal: str,
    vpn_user_groups: Optional[list[str]],
    vpn_os: Optional[str],
    connection_name: str,
    connection_uuid: str,
    openconnect_args: Optional[list[str]],
) -> None:
    """Get the cookie (SAML auth) and necessary data to connect to the GlobalProtect VPN using `nmcli`"""

    def get_url_for_saml_authentication() -> str:
        """Get URL to perform SAML authentication"""
        url_for_saml_auth: str = ""
        try:
            # i.e: openconnect --non-inter --protocol=gp --usergroup=gateway --os=win portal.test.com
            command_to_obtain_url: list[str] = [
                "openconnect",
                "--non-inter",
                "--protocol=gp",
                f"--usergroup={vpn_user_groups[0]}" if vpn_user_groups is not None and len(vpn_user_groups) else "",
                f"--os={vpn_os}" if vpn_os is not None and len(vpn_os) else "",
                openconnect_args[0] if openconnect_args is not None and len(openconnect_args) else "",
                vpn_portal,
            ]
            command_to_obtain_url_str: str = " ".join([x for x in command_to_obtain_url if len(x)])
            print("1. Getting URL to perform SAML authentication...")
            print(f'Running command: "{command_to_obtain_url_str}"\n')
            proc: subprocess.Popen[str] = subprocess.Popen(
                args=["bash", "-c", f"LANG=en {command_to_obtain_url_str}"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            proc.wait()
            if proc.stdout is not None:
                for line in proc.stdout:
                    if not "SAML REDIRECT" in line:
                        continue
                    else:
                        url_for_saml_auth = line.replace("\n", "").removeprefix(
                            "SAML REDIRECT authentication is required via "
                        )
                        break
        except Exception as e:
            print(f"An error occurred obtaining URL to perform SAML authentication, exception: {e}")
            traceback.print_tb(tb=e.__traceback__)
        finally:
            if not len(url_for_saml_auth):
                print("No URL was found to perform SAML authentication, try again.")
            return url_for_saml_auth

    def get_cookie_and_username(url: str) -> tuple[str, str]:
        cookie: str = ""
        username: str = ""
        try:
            print("2. Performing SAML authentication, opening selenium browser...\n")
            chrome_options: webdriver.ChromeOptions = webdriver.ChromeOptions()
            chrome_options.add_argument(argument="--window-size=800,600")
            chrome_options.add_argument(argument=f"--user-data-dir={str(CONFIG_FOLDER)}")
            chrome_options.add_argument(argument="--disable-session-crashed-bubble")
            chrome_options.add_argument(argument="--hide-crash-restore-bubble")
            chrome_options.add_experimental_option(name="useAutomationExtension", value=False)
            chrome_options.add_experimental_option(name="excludeSwitches", value=["enable-automation"])
            driver: WebDriver = webdriver.Chrome(options=chrome_options)
            driver.get(url=url)
            WebDriverWait(driver=driver, timeout=180).until(
                lambda driver: "login successful" in driver.page_source.lower()
                and any(s in driver.page_source.lower() for s in ("prelogin-cookie", "portal-userauthcookie"))
            )
            xml_string: ET.Element = ET.fromstring(
                text=driver.page_source, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
            )
            xml_element_with_cookie_and_username: Optional[ET.Element] = None
            for node in xml_string.iter():
                if not node.text:
                    continue
                if "saml-username" in node.text.lower() and any(
                    s in node.text.lower() for s in ("prelogin-cookie", "portal-userauthcookie")
                ):
                    xml_element_with_cookie_and_username = ET.fromstring(text=f"<body>{node.text.strip()}</body>")
                    break
            if xml_element_with_cookie_and_username is not None:
                for node in xml_element_with_cookie_and_username.iter():
                    if not node.text:
                        continue
                    if "saml-username" in node.tag.lower():
                        username = node.text.replace(
                            "\\", "\\\\"  # Backslashes need to be escaped if they're part of the username.
                        )
                    elif "cookie" in node.tag.lower():
                        cookie = node.text
                    if len(username) and len(cookie):
                        break
        except TimeoutException:
            print("Timed out waiting for authentication, try again.")
        except NoSuchWindowException:
            print("The window was closed before finishing the authentication, try again.")
        except Exception as e:
            print(f"An error occurred performing SAML authentication, exception: {e}")
            traceback.print_tb(tb=e.__traceback__)
        finally:
            if not len(cookie) or not len(username):
                print("No cookie or username was obtained when performing SAML authentication, try again.")
            return cookie, username

    def get_secrets_for_nmcli(prelogin_cookie: str, username: str) -> tuple[str, str, str, str]:
        cookie: str = ""
        fingerprint: str = ""
        host: str = ""
        resolve: str = ""
        try:
            # i.e: openconnect --protocol=gp --user=someuser@company.com --usergroup=gateway:prelogin-cookie --passwd-on-stdin --authenticate --os=win portal.test.com
            command_to_obtain_vpn_secrets: list[str] = [
                "openconnect",
                "--protocol=gp",
                f"--user={username}",
                (
                    (
                        f"--usergroup={vpn_user_groups[0]}:prelogin-cookie"
                        if vpn_user_groups[0] == "gateway" and len(vpn_user_groups) == 1
                        else (
                            f"--usergroup={vpn_user_groups[0]}:portal-userauthcookie"
                            if vpn_user_groups[0] == "portal" and len(vpn_user_groups) == 1
                            else (f"--usergroup={vpn_user_groups[1]}" if len(vpn_user_groups) == 2 else "")
                        )
                    )
                    if vpn_user_groups is not None and len(vpn_user_groups)
                    else ""
                ),
                "--passwd-on-stdin",
                "--authenticate",
                f"--os={vpn_os}" if vpn_os is not None and len(vpn_os) else "",
                openconnect_args[1] if openconnect_args is not None and len(openconnect_args) == 2 else "",
                vpn_portal,
            ]
            command_to_obtain_vpn_secrets_str: str = (
                f"echo {prelogin_cookie} | {' '.join([x for x in command_to_obtain_vpn_secrets if len(x)])}"
            )
            print("3. Getting vpn secrets for nmcli...")
            print(f'Running command: "{command_to_obtain_vpn_secrets_str}"\n')
            secrets: subprocess.Popen[str] = subprocess.Popen(
                args=["bash", "-c", f"export LANG=en && {command_to_obtain_vpn_secrets_str}"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            secrets.wait()
            vpn_secrets_dict: dict[str, str] = {}
            for line in cast(IO[str], secrets.stdout):
                line = line.replace("\n", "")
                properties_to_search: list[str] = ["COOKIE", "FINGERPRINT", "HOST", "RESOLVE", "CONNECT_URL"]
                for property_ in properties_to_search:
                    if not line.startswith(property_):
                        continue
                    value_of_property: str = line.split(sep="=", maxsplit=1)[1].replace("'", "")
                    vpn_secrets_dict[property_] = value_of_property
            if len(vpn_secrets_dict):
                print("  Secrets Obtained: ")
                for key, value in vpn_secrets_dict.items():
                    print(f"    {key}={value}")
                try:
                    cookie = vpn_secrets_dict["COOKIE"]
                    fingerprint = vpn_secrets_dict["FINGERPRINT"]
                    host = vpn_secrets_dict["HOST"]
                    resolve = vpn_secrets_dict["RESOLVE"]
                except KeyError:
                    pass
        except Exception as e:
            print(f"An error occurred getting the vpn secrets for nmcli, exception: {e}")
            traceback.print_tb(tb=e.__traceback__)
        finally:
            if not len(cookie) or not len(fingerprint) or not len(host) or not len(resolve):
                print("Could not obtain all the vpn secrets for nmcli, try again.")
            return cookie, fingerprint, host, resolve

    def connect_using_nmcli(cookie: str, fingerprint: str, host: str, resolve: str) -> None:
        try:
            vpn_secrets_for_nmcli: list[str] = [
                f"vpn.secrets.cookie:{cookie}",
                f"vpn.secrets.gwcert:{fingerprint}",
                f"vpn.secrets.gateway:{host}",
                f"vpn.secrets.resolve:{resolve}",
            ]
            text_with_vpn_secrets_for_nmcli: str = "\\n".join(vpn_secrets_for_nmcli)
            command_to_connect_to_vpn: str = (
                f"printf '{text_with_vpn_secrets_for_nmcli.replace('%', '%%')}' | nmcli connection up uuid '{connection_uuid}' passwd-file /dev/stdin"
            )
            print(f'\n4. Connecting to VPN "{connection_name}" with uuid "{connection_uuid}" using nmcli...')
            print(f'Running command: "{command_to_connect_to_vpn}"\n')
            subprocess.check_call(args=["bash", "-c", f"export LANG=en && {command_to_connect_to_vpn}"])
        except Exception as e:
            print(f'An error occurred connecting to "{connection_name}" with uuid "{connection_uuid}", exception: {e}')
            traceback.print_tb(tb=e.__traceback__)

    url_for_saml_auth: str = get_url_for_saml_authentication()
    if not len(url_for_saml_auth):
        return

    prelogin_cookie, username = get_cookie_and_username(url=url_for_saml_auth)
    if not len(prelogin_cookie) or not len(username):
        return

    cookie, fingerprint, host, resolve = get_secrets_for_nmcli(prelogin_cookie=prelogin_cookie, username=username)
    if not len(cookie) or not len(fingerprint) or not len(host) or not len(resolve):
        return

    connect_using_nmcli(cookie=cookie, fingerprint=fingerprint, host=host, resolve=resolve)


class CLIArguments(NamedTuple):
    connection_name: str
    vpn_portal_gateway: str
    vpn_user_groups: Optional[list[str]]
    vpn_os: Optional[str]
    openconnect_args: Optional[list[str]]


def parse_cli_arguments() -> CLIArguments:
    # CLI arguments
    parser: ArgumentParser = ArgumentParser(
        prog=APP_NAME,
        description=(
            "Connect to a Glopal Protect VPN connection that requires SAML authenticaton using nmcli and openconnect."
        ),
    )
    parser.add_argument(
        "--connection-name",
        help="Name for the connection to add with nmcli if it's not already created.",
        required=True,
    )
    parser.add_argument(
        "--vpn-portal", "--vpn-gateway", help="Address of the portal/gateway of the Global Protect VPN.", required=True
    )
    parser.add_argument(
        "--vpn-user-groups",
        help=(
            "Usergroups to pass to openconnect's --usergroup parameter. It can be a single value or 2 values. "
            "The first value is used when using openconnect to get the URL to perform the SAML authentication and "
            "the second one is used when using openconnect to perform the VPN authentication. "
            "If the value for this parameter is only 'gateway' then 'gateway' will be used as the --usergroup parameter to get the URL for SAML authentication "
            "and for the VPN authentication the --usergroup parameter will be 'gateway:prelogin-cookie'. "
            "If the value for this parameter is only 'portal' then 'portal' will be used as the --usergroup parameter to get the URL for SAML authentication "
            "and for the VPN authentication the --usergroup parameter will be 'portal:portal-userauthcookie'."
        ),
        nargs="*",
        metavar=("VPN_USER_GROUP_GET_URL_SAML", "VPN_USER_GROUP_CONNECT_VPN"),
    )
    parser.add_argument(
        "--vpn-os",
        help="OS to pass to openconnect's --os parameter. Options can be: 'linux', 'linux-64', 'win', 'mac-intel', 'android', 'apple-ios'.",
    )
    parser.add_argument(
        "--openconnect-args",
        help=(
            "Extra arguments to pass to openconnect. It can be a single value or 2 values, make sure to add quotes to distinguish from the normal arguments of the application. "
            "The first value contains the extra openconnect arguments used to get the URL to perform the SAML authentication and "
            "the second one contains the extra openconnect arguments used to perform the VPN authentication. "
            'Example: --openconnect-args "--extra-arg=value --another-arg=value" "--extra-arg=value"'
        ),
        nargs="*",
        metavar=("OPENCONNECT_ARGS_GET_URL_SAML", "OPENCONNECT_ARGS_CONNECT_VPN"),
    )

    # Parse arguments
    args: Namespace = parser.parse_args()
    cli_arguments: CLIArguments = CLIArguments(
        connection_name=args.connection_name,
        vpn_portal_gateway=args.vpn_portal,
        vpn_user_groups=(
            [x.strip() for x in cast(list[str], args.vpn_user_groups) if len(x.strip())]
            if args.vpn_user_groups is not None and len(args.vpn_user_groups)
            else None
        ),
        vpn_os=args.vpn_os.strip() if args.vpn_os is not None and len(args.vpn_os.strip()) else None,
        openconnect_args=(
            [x.strip() for x in cast(list[str], args.openconnect_args) if len(x.strip())]
            if args.openconnect_args is not None and len(args.openconnect_args)
            else None
        ),
    )
    if cli_arguments.vpn_user_groups is not None and len(cli_arguments.vpn_user_groups) > 2:
        parser.error(message="The optional parameter --vpn-user-groups can only contain one or two values.")
    if cli_arguments.openconnect_args is not None and len(cli_arguments.openconnect_args) > 2:
        parser.error(message="The optional parameter --openconnect-args can only contain one or two values.")
    if cli_arguments.openconnect_args is not None:
        for openconnect_args in cli_arguments.openconnect_args:
            if any(
                x in openconnect_args for x in ("usergroup ", "os ", "--usergroup ", "--os ", "--usergroup=", "--os=")
            ):
                parser.error(
                    message="The value/s for the optional parameter --openconnect-args can't contain the arguments '--usergroup' or '--os' since those arguments can be defined as normal arguments of the application."
                )
    return cli_arguments


def main() -> None:
    """Main function"""
    # Get arguments from command line
    arguments: CLIArguments = parse_cli_arguments()

    # Check if connection exists if not create it
    uuid_of_connection: Optional[str] = create_connection(
        connection_name=arguments.connection_name, vpn_portal=arguments.vpn_portal_gateway, vpn_os=arguments.vpn_os
    )

    # Check if the uuid for the connection exists
    if uuid_of_connection is None:
        return

    # Check if connection is already connected
    if connection_is_active(connection_name=arguments.connection_name, connection_uuid=uuid_of_connection):
        return

    # Do SAML auth and get cookie and necessary vpn secrets to connect to the VPN via nmcli
    connect_to_vpn_using_nmcli(
        vpn_portal=arguments.vpn_portal_gateway,
        vpn_user_groups=arguments.vpn_user_groups,
        vpn_os=arguments.vpn_os,
        connection_name=arguments.connection_name,
        connection_uuid=uuid_of_connection,
        openconnect_args=arguments.openconnect_args,
    )


# Globals
APP_NAME: str = "connect_to_global_protect_vpn_using_nmcli"
CONFIG_FOLDER: Path = Path.home().joinpath(".config", APP_NAME)

if __name__ == "__main__":
    main()
