# hosts.py - Ansible module to update hosts file
# Author: Carlos Huchim Ahumada (@huchim)
# License: GPL-3.0-or-later
from __future__ import annotations
from ansible.module_utils.basic import AnsibleModule
from ipaddress import ip_address
import json
import yaml


DOCUMENTATION = """
    name: hosts
    author: Carlos Huchim Ahumada (@huchim)
    version_added: "1.0.0"
    short_description: A module to update hosts file.
    description:
      - This module updates the hosts file with the specified IP address and hostname.
    options:
      hosts:
        ip:
            description: IP address to be added to the hosts file.
            type: str
            required: true
            default:
        names:
            description: Hostnames to be added to the hosts file.
            type: list
            required: true
        state:
            description: Whether to add or remove the hostnames.
            type: str
            choices: [present, absent]
            default: present
        os:
            description: Operating system type.
            type: str
            choices: [linux, windows]
            default: linux
"""

EXAMPLES = """
# hosts module example

- name: Ensure hosts file is updated
  desosu.general.hosts:
    - ip: 192.168.0.100
      names:
        - foo.example.local
      os: windows
"""


class Entry:
    """
    Represents an entry in the host file.

    An entry can be an IP address, a comment, or an empty line.
    """

    __ip: str
    hostnames: list[str]
    backup: list[str]
    touched: bool = False

    def __init__(self, ip, hostnames, touched=False, backup=None):
        """
        Initializes a new instance of Entry.

        :param ip: The IP address or comment.
        :param hostnames: The list of hostnames or aliases.
        :param touched: Indicates if the entry has been modified.
        """
        self.__ip = ip
        self.hostnames = hostnames
        self.touched = touched
        self.backup = backup if backup else hostnames.copy()

    def clear_hostnames(self):
        """Clear the hostnames of the entry."""
        self.__touch()
        self.hostnames = []

    def changed(self) -> bool:
        """Check if the entry has changes."""
        return self.touched

    def update_hostnames(self, hostnames: list[str], remove: bool = False) -> list[str]:
        """
        Update the hostnames of the entry.

        - If the hostname does not exist in the entry, it will be added.
        - If the hostname exists in the entry, it will be removed.

        :param hostnames: The new list of hostnames.
        """
        # Remove in hostname_alias all not in alias
        # Add in hostname_alias all in alias
        if remove:
            for hostname in self.hostnames:
                if hostname not in hostnames:
                    self.remove_hostname(hostname)

        for hostname in hostnames:
            self.append_hostname(hostname)

        return self.hostnames

    def append_hostname(self, hostname):
        """Append a hostname to the entry."""
        if hostname not in self.hostnames:
            self.__touch()
            self.hostnames.append(hostname)

    def remove_hostname(self, hostname):
        """Remove a hostname from the entry."""
        if hostname in self.hostnames:
            self.__touch()
            self.hostnames.remove(hostname)

    def get_ip(self) -> str:
        """Get the IP address."""
        return self.__ip.strip()

    def get_compressed_ip(self) -> str:
        """Get the compressed IP address."""
        if self.get_type() != "entry":
            # Throw an exception if the entry is not an IP address
            raise ValueError(f"Entry {self.__ip} is not an IP address")

        if self.get_ip_type() == "ipv6":
            return ip_address(self.get_ip()).compressed

        return self.get_ip()

    def get_ip_type(self) -> str:
        """Get the type of IP address."""
        if self.get_type() != "entry":
            # Throw an exception if the entry is not an IP address
            raise ValueError(f"Entry {self.__ip} is not an IP address")

        if ":" in self.__ip:
            return "ipv6"

        if "." in self.__ip:
            return "ipv4"

        # Raise an exception if the entry is not an IP address
        raise ValueError(f"Entry {self.__ip} is not an IP address")

    def get_type(self) -> str:
        """Get the type of entry."""
        if self.__ip == "#":
            return "comment"
        elif self.__ip == "-":
            return "empty"
        else:
            return "entry"

    def __touch(self):
        """Mark the entry as touched."""
        self.touched = True


class Entries:
    """
    Represents a list of entries in the host file.
    """

    def __init__(self, entries: list[Entry]):
        self.entries = entries

    def is_touched(self) -> bool:
        """Check if any entry is touched."""
        touched = self.get_touched_entries()

        return len(touched) > 0

    def get_touched_entries(self) -> list[Entry]:
        """Get the touched entries."""
        touched_entries = []

        for entry in self.entries:
            if entry.changed():
                touched_entries.append(entry)

        return touched_entries

    def get_output(
        self,
        entries: list[Entry] = None,
        justify: bool = True,
        use_backup: bool = False,
        entries_only: bool = False,
    ) -> str:
        """Get the output of the entries."""
        output = []
        m_entries = entries if entries is not None else self.entries

        for entry in m_entries:
            if entries_only and entry.get_type() != "entry":
                continue

            hostnames = entry.backup if use_backup else entry.hostnames

            if entry.get_type() == "comment":
                output.append(f"{hostnames[0]}")
            elif entry.get_type() == "empty":
                output.append("")
            elif entry.get_type() == "entry":
                ip = (
                    entry.get_compressed_ip().ljust(39)
                    if justify
                    else entry.get_compressed_ip()
                )

                if len(hostnames) > 0:
                    output.append(f"{ip} {' '.join(hostnames)}".strip())
            else:
                pass

        return "\n".join(output) + "\n"

    def write_file(self, filename):
        """Write the entries to a file."""
        output = self.get_output()

        with open(filename, "w", encoding="utf-8") as file:
            file.write(output)

    def validate(self):
        """
        Validate the entries.

        - All alias must be unique
        """
        # Get all aliases
        ips = set()
        aliases = set()

        for entry in self.entries:
            if entry.get_type() != "entry":
                continue

            entry.get_ip_type()
            ip = ip_address(entry.get_ip()).exploded

            if ip in ips:
                # Warns if the IP address is already in the list
                print(
                    f"Warning: Duplicate IP address {ip} found in entry {entry.get_ip()}",
                )

            ips.add(ip)

            for hostname in entry.hostnames:
                if hostname in aliases:
                    raise ValueError(
                        f"Duplicate alias {hostname} found in entry {entry.get_ip()}",
                    )

                aliases.add(hostname)

    def update_alias(self, ip: str, hostnames: list[str]):
        """
        Update the alias of an entry.

        This method will not remove others hostnames for the IP.
        """
        entries = self.find_by_ip(ip)

        if len(entries) == 0:
            # Get the last entry to get the last line number
            entry = Entry(ip, hostnames, True, [])

            entries.append(entry)
            self.entries.append(entry)

        x = self.__get_distinct_hostnames(entries)

        # Remove all hostnames that are not in the new list
        for hostname in hostnames:
            if hostname not in x:
                x.append(hostname)

        # Update the hostnames of the entry
        entries[0].update_hostnames(x)

        for entry in entries[1:]:
            entry.clear_hostnames()

    def find_by_ip(self, ip) -> list[Entry]:
        """Find entries by IP address."""
        entries = []

        for entry in self.entries:
            if entry.get_type() != "entry":
                continue

            c_ip = ip_address(ip).compressed

            # IP is the first element in the list
            if c_ip == entry.get_compressed_ip():
                entries.append(entry)

        return entries

    def __get_distinct_hostnames(self, entries: list[Entry]) -> list[str]:
        """Get distinct hostnames from the entries."""

        hostnames = set()

        for entry in entries:
            if entry.get_type() != "entry":
                continue

            for hostname in entry.hostnames:
                if hostname not in hostnames:
                    hostnames.add(hostname)

        return list(hostnames)


class HostFile:
    """
    Represents the host file.
    """

    def create_entries(filename: str) -> Entries:
        """Read the host file and store entries."""

        entries: list[Entry] = []

        with open(filename, "r", encoding="utf-8") as file:
            line_number = 0

            for line in file:
                line_number += 1

                # Ignore empty lines and lines starting with '#'
                if line.strip() == "":
                    entries.append(Entry("-", []))
                    continue

                if line.strip().startswith("#"):
                    entries.append(Entry("#", [line[:-1]]))
                    continue

                # Find the position of the first "#", if not found it will be -1
                hash_index = line.find("#")
                line_to_evaluate = line[:hash_index] if hash_index != -1 else line

                # Split the line into IP and hostname/alias
                values = line_to_evaluate.strip().split()
                entries.append(Entry(values[0], values[1:]))

        return Entries(entries)


def main():
    # Definir los argumentos del módulo
    # Este módulos acepta un argumento llamado "hosts" que es una lista donde "ip" es la dirección IP y "names" son los nombres de host
    module_args = dict(
        hosts=dict(
            type="list",
            elements="dict",
            options=dict(
                ip=dict(type="str", required=True),
                names=dict(type="list", elements="str", required=True),
                state=dict(
                    type="str",
                    choices=["present", "absent"],
                    default="present",
                ),
                os=dict(
                    type="str",
                    choices=["linux", "windows"],
                    default="linux",
                ),
            ),
        ),
        # host_file
        config_file=dict(
            type="str",
            required=False,
        ),
    )

    # Crear el módulo
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    # El formato define:
    #  - Cada entrada como IP_address canonical_hostname [aliases...]
    #  - Los comentarios comienzan con un símbolo de número (#) y se extienden hasta el final de la línea
    #  - Cuando se encuentre un # se considerará un comentario hasta el final de la línea
    # Examples:
    #  - ::1             localhost ip6-localhost ip6-loopback
    #  - 127.0.0.1       localhost
    # Fuentes:
    # https://man7.org/linux/man-pages/man5/hosts.5.html
    # https://www.ibm.com/docs/en/aix/7.2?topic=formats-hosts-file-format-tcpip

    # Resultado del módulo
    result = dict(
        changed=False,
    )

    hosts_params = module.params["hosts"] if module.params["hosts"] is not None else []

    if module.params["config_file"] is not None:
        if module.params["hosts"] is not None:
            module.fail_json(
                msg="No se puede especificar config_file y hosts al mismo tiempo",
            )

        # Check if the file exists
        try:
            with open(module.params["config_file"], "r", encoding="utf-8") as _:
                pass
        except FileNotFoundError:
            module.fail_json(msg=f"El archivo {module.params['config_file']} no existe")

        # Parse JSON file.
        try:
            with open(module.params["config_file"], "r", encoding="utf-8") as file:
                hosts_params = json.load(file)

                # Set defaults
                for host in hosts_params:
                    if "state" not in host:
                        host["state"] = "present"

                    if "os" not in host:
                        host["os"] = "linux"

        except json.JSONDecodeError:
            module.fail_json(
                msg=f"Error al analizar el archivo JSON {module.params['config_file']}",
            )
        except Exception as e:
            module.fail_json(
                msg=f"Error al leer el archivo {module.params['config_file']}: {str(e)}",
            )

    if len(hosts_params) == 0:
        module.fail_json(msg="No se han proporcionado hosts para actualizar")

    try:
        # Leer el archivo /etc/hosts
        entries = HostFile.create_entries("/etc/hosts")

        for host in hosts_params:
            if host["state"] == "absent":
                # Find the entries by IP address
                absent_entries = entries.find_by_ip(host["ip"])

                for entry in absent_entries:
                    # Remove the hostnames from the entry
                    for h in host["names"]:
                        entry.remove_hostname(h)

                continue

            ip = host["ip"]
            names = host["names"]

            # Actualizar las entradas
            entries.update_alias(ip, names)

        # Write the entries to the file
        if not module.check_mode:
            # entries.validate()
            entries.write_file("/etc/hosts")

        result["changed"] = entries.is_touched()

        if module.check_mode and module._diff and result["changed"]:
            touched = entries.get_touched_entries()

            # If diff mode
            before = entries.get_output(
                touched,
                justify=False,
                use_backup=True,
                entries_only=True,
            ).strip()
            after = entries.get_output(
                touched,
                justify=False,
                entries_only=True,
            ).strip()
            result["diff"] = dict(
                before=yaml.safe_dump(before, default_flow_style=False),
                after=yaml.safe_dump(after, default_flow_style=False),
            )
    except Exception as e:
        # Manejo de errores en caso de que no se pueda leer el archivo
        module.fail_json(msg=str(e))

    # Salida del módulo
    module.exit_json(**result)


if __name__ == "__main__":
    main()
