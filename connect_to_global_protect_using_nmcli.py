import subprocess
import tempfile
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
                        f'Connection "{connection_name}" with uuid "{uuid_of_desired_connection}" for vpn protocol'
                        f' "gp" and vpn portal "{vpn_portal}" found, using it to connect with nmcli...'
                    )
                    break
            except:
                pass
    if uuid_of_desired_connection is None:  # Create connection
        try:
            msg: str = (
                f'Creating connection with name "{connection_name}", vpn protocol'
                f' "gp"{"," if vpn_os is not None else " and"} vpn gateway "{vpn_portal}"'
            )
            msg += f' and reported os "{vpn_os}"' if vpn_os is not None else ""
            msg += "..."
            print(msg)
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
            result_of_created_connection: str = subprocess.check_output(
                args=[
                    "bash",
                    "-c",
                    (
                        f"LANG=en nmcli connection add con-name '{connection_name}' type vpn vpn-type openconnect"
                        f" vpn.data {','.join(f'{k}={v}' for k,v in vpn_data.items())}"
                    ),
                ],
                text=True,
            ).replace("\n", "")
            uuid_of_desired_connection = result_of_created_connection.split(sep="(")[1].split(sep=")")[0]
            print(
                f'Connection "{connection_name}" successfully created, uuid of new connection:'
                f' "{uuid_of_desired_connection}"'
            )
        except Exception as e:
            print(f'An error occurred creating connection "{connection_name}", exception: {e}')
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
    vpn_user_group: str,
    vpn_os: Optional[str],
    connection_name: str,
    connection_uuid: str,
    openconnect_args: Optional[str],
) -> None:
    """Get the cookie (SAML auth) and necessary data to connect to the GlobalProtect VPN using `nmcli`"""

    def get_url_for_saml_authentication() -> str:
        url_for_saml_auth: str = ""
        try:
            print("Getting URL to perform SAML authentication...")
            proc: subprocess.Popen[str] = subprocess.Popen(
                args=[
                    "bash",
                    "-c",
                    (
                        "LANG=en openconnect --protocol=gp"
                        f" --usergroup={vpn_user_group} {f'--os={vpn_os} ' if vpn_os is not None else ''}{vpn_portal}"
                    ),
                ],
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
        finally:
            if not len(url_for_saml_auth):
                print("No URL was found to perform SAML authentication, try again.")
            return url_for_saml_auth

    def get_cookie_and_username(url: str) -> tuple[str, str]:
        cookie: str = ""
        username: str = ""
        try:
            print("Performing SAML authentication, opening selenium browser...")
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
                and any(s.lower() in driver.page_source.lower() for s in ("prelogin-cookie", "portal-userauthcookie"))
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
                        username = node.text
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
            print("Getting vpn secrets for nmcli...")
            secrets: subprocess.Popen[str] = subprocess.Popen(
                args=[
                    "bash",
                    "-c",
                    (
                        f"echo {prelogin_cookie} | LANG=en openconnect --protocol=gp"
                        f" --user={username} --usergroup={vpn_user_group}:prelogin-cookie --passwd-on-stdin"
                        f" --authenticate{f' --os={vpn_os} ' if vpn_os is not None else ''}{f' {openconnect_args}' if openconnect_args is not None else ''} {vpn_portal}"
                    ),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            secrets.wait()
            for line in cast(IO[str], secrets.stdout):
                line = line.replace("\n", "")
                if line.startswith("COOKIE"):
                    cookie = line.split(sep="=", maxsplit=1)[1].replace("'", "")
                elif line.startswith("FINGERPRINT"):
                    fingerprint = line.split(sep="=", maxsplit=1)[1].replace("'", "")
                elif line.startswith("HOST"):
                    host = line.split(sep="=", maxsplit=1)[1].replace("'", "")
                elif line.startswith("RESOLVE"):
                    resolve = line.split(sep="=", maxsplit=1)[1].replace("'", "")
        except Exception as e:
            print(f"An error occurred getting the vpn secrets for nmcli, exception: {e}")
        finally:
            if not len(cookie) or not len(fingerprint) or not len(host) or not len(resolve):
                print("Could not obtain all the vpn secrets for nmcli, try again.")
            return cookie, fingerprint, host, resolve

    def connect_using_nmcli(cookie: str, fingerprint: str, host: str, resolve: str) -> None:
        print(f'Connecting to network "{connection_name}" with uuid "{connection_uuid}" using nmcli...')
        path_of_file: str = ""
        with tempfile.NamedTemporaryFile(mode="w", prefix=APP_NAME, delete=False) as tf:
            path_of_file = tf.name
            tf.write(f"vpn.secrets.cookie:{cookie}\n")
            tf.write(f"vpn.secrets.gwcert:{fingerprint}\n")
            tf.write(f"vpn.secrets.gateway:{host}\n")
            tf.write(f"vpn.secrets.resolve:{resolve}")
        try:
            subprocess.check_call(
                args=["bash", "-c", f"LANG=en nmcli connection up uuid {connection_uuid} passwd-file {path_of_file}"]
            )
        except Exception as e:
            print(f'An error occurred connecting to "{connection_name}" with uuid "{connection_uuid}", exception: {e}')
        finally:
            Path(path_of_file).unlink(missing_ok=True)

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


class Arguments(NamedTuple):
    connection_name: str
    vpn_portal_gateway: str
    vpn_user_group: str
    vpn_os: Optional[str]
    openconnect_args: Optional[str]


def parse_cli_arguments() -> Arguments:
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
        "--vpn-user-group",
        help="Usergroup to pass to openconnect --usergroup parameter. Defaults to 'portal'",
        choices=["portal", "gateway"],
        default="portal",
    )
    parser.add_argument(
        "--vpn-os",
        help=f"OS to pass to openconnect --os parameter.",
        choices=["linux", "linux-64", "win", "mac-intel", "android", "apple-ios"],
    )
    parser.add_argument("--openconnect-args", help="Extra arguments to pass to openconnect.")

    # Parse arguments
    args: Namespace = parser.parse_args()
    return Arguments(
        connection_name=args.connection_name,
        vpn_portal_gateway=args.vpn_portal,
        vpn_user_group=args.vpn_user_group,
        vpn_os=args.vpn_os,
        openconnect_args=args.openconnect_args,
    )


def main() -> None:
    """Main function"""
    # Get arguments from command line
    arguments: Arguments = parse_cli_arguments()

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
        vpn_user_group=arguments.vpn_user_group,
        vpn_os=arguments.vpn_os,
        connection_name=arguments.connection_name,
        connection_uuid=uuid_of_connection,
        openconnect_args=arguments.openconnect_args,
    )


# Globals
APP_NAME: str = "connect_to_global_protect_using_nmcli"
CONFIG_FOLDER: Path = Path.home().joinpath(".config", APP_NAME)

if __name__ == "__main__":
    main()
