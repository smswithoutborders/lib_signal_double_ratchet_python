"""
System Dependency Installer Script

This script detects the operating system and installs the necessary system 
dependencies.

Usage:
    Run the script directly to install the dependencies:
    $ python3 install_system_deps.py
"""

import platform
import subprocess
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s:\t%(message)s")


def install_package(package_name):
    """
    Install a Python package using pip.

    Args:
        package_name (str): The name of the package to install.
    """
    subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])


try:
    import distro
except ImportError:
    logging.info("Installing the 'distro' package...")
    install_package("distro")
    import distro


def check_sudo():
    """
    Check if sudo is available on the system.

    Returns:
        bool: True if sudo is available, False otherwise.
    """
    try:
        subprocess.check_call(["sudo", "-n", "true"])
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_system_deps():
    """
    Install system dependencies based on the operating system.

    This function detects the operating system and installs the necessary
    dependencies.

    Raises:
        Exception: If the operating system or distribution is unsupported.
    """
    os_type = platform.system().lower()

    if os_type == "linux":
        pretty_name = distro.name(pretty=True)
        logging.info("Detected Linux distribution: %s", pretty_name)

        distro_id = distro.id().lower()
        distro_like = distro.like().lower().split()

        sudo_available = check_sudo()

        if sudo_available:
            try:
                if distro_id == "arch" or "arch" in distro_like:
                    logging.info("Installing sqlcipher on Arch Linux...")
                    subprocess.check_call(
                        ["sudo", "pacman", "-S", "--noconfirm", "sqlcipher"]
                    )
                elif distro_id in ["ubuntu", "debian"] or "debian" in distro_like:
                    logging.info("Installing sqlcipher on Debian/Ubuntu...")
                    subprocess.check_call(["sudo", "apt", "update"])
                    subprocess.check_call(
                        [
                            "sudo",
                            "apt",
                            "install",
                            "-y",
                            "libsqlcipher-dev",
                            "build-essential",
                            "git",
                            "cmake",
                            "libsqlite3-dev",
                            "sqlcipher",
                        ]
                    )
                else:
                    logging.error("Unsupported Linux distribution: %s", pretty_name)
            except subprocess.CalledProcessError as e:
                logging.error("Error installing system dependencies: %s", e)
                logging.info("Please install the following dependencies manually:")
                if distro_id == "arch" or "arch" in distro_like:
                    logging.info("Arch Linux: sudo pacman -S sqlcipher")
                elif distro_id in ["ubuntu", "debian"] or "debian" in distro_like:
                    logging.info("Debian/Ubuntu: sudo apt install libsqlcipher-dev")
                    logging.info(
                        "Debian/Ubuntu: sudo apt install build-essential git cmake libsqlite3-dev"
                    )
                    logging.info("Debian/Ubuntu: sudo apt install sqlcipher")
            except Exception as e:
                logging.error("An unexpected error occurred: %s", e)
                raise
        else:
            logging.error("Please run this script with sudo privileges.")
            logging.info("Example usage: sudo python3 install_system_deps.py")
    else:
        logging.error("Unsupported operating system: %s", os_type)


if __name__ == "__main__":
    install_system_deps()
