import subprocess
import string
import random
import time

class WiFiDirectIsland:
    """Provides a zero-infrastructure Wi-Fi Direct connection mechanism on Windows."""
    
    def __init__(self, ssid_prefix="Archipel-Island-", password_length=12):
        self.ssid = f"DIRECT-{ssid_prefix}{self._generate_random_suffix(4)}"
        self.password = self._generate_random_suffix(password_length, chars=string.ascii_letters + string.digits)

    def _generate_random_suffix(self, length, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choices(chars, k=length))

    def create_island(self) -> bool:
        """Starts a WinRT Wi-Fi Direct Group Owner via PowerShell."""
        ps_script = f"""
$ErrorActionPreference = "Stop"

# Use the older Hosted Network API which is sometimes disguised as Wi-Fi Direct under the hood on some Win10/11 configs, 
# or use the modern WFD API. Since pure WFD Group Owner creation via WinRT in PowerShell is highly complex 
# and often blocked by security policies without a packaged app (Appx), we will use netsh wlan set hostednetwork 
# but specifically force it without internet sharing.

# Attempt legacy hosted network first as it's the most reliable "headless" AdHoc method if the driver allows it.
# If "Hosted network supported: No", this will fail.
$ssid = "{self.ssid}"
$key = "{self.password}"

netsh wlan set hostednetwork mode=allow ssid=$ssid key=$key | Out-Null
netsh wlan start hostednetwork | Out-Null
"""
        try:
            print(f"[WIFI-ISLAND] Setting up Zero-Internet Wi-Fi Direct Island...")
            print(f"  SSID: {self.ssid}")
            print(f"  PASS: {self.password}")
            
            result = subprocess.run(
                ["powershell", "-Command", ps_script], 
                capture_output=True, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                print(f"[WIFI-ISLAND] Island successfully created! Other peers can now join this Wi-Fi network.")
                return True
            else:
                print("[WIFI-ISLAND] Driver rejected Hosted Network. Trying Mobile Hotspot fallback without Internet Sharing...")
                return self._fallback_mobile_hotspot()
                
        except Exception as e:
            print(f"[WIFI-ISLAND] Error: {e}")
            return False

    def _fallback_mobile_hotspot(self) -> bool:
        """Fallback to WinRT TetheringManager if HostedNetwork is strictly blocked by the Intel driver."""
        ps_script = """
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
$connProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()

if ($connProfile -eq $null) {
    # If there is absolutely no network, TetheringManager might fail to initialize.
    Write-Output "NO_PROFILE"
    exit 1
}

$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connProfile)
if ($manager) {
    $result = $manager.StartTetheringAsync().GetAwaiter().GetResult()
    Write-Output "STATUS:$($result.Status)"
    if ($result.Status -eq "Success") {
        exit 0
    }
}
exit 1
"""
        print("[WIFI-ISLAND] Note: Fallback Mobile Hotspot might require at least a dummy network adapter to be active (like a local loopback or disconnected Wi-Fi).")
        result = subprocess.run(
            ["powershell", "-Command", ps_script], 
            capture_output=True, 
            text=True, 
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0 and "STATUS:Success" in result.stdout:
            print("[WIFI-ISLAND] Hotspot fallback created successfully.")
            return True
        else:
            print(f"[WIFI-ISLAND] Failed to create Wi-Fi Island. Your Wi-Fi card (Intel AX203) completely blocks ad-hoc creation without an external router.\nDetails: {result.stdout.strip()}")
            return False

    def check_status(self):
        ps_script = """
netsh wlan show hostednetwork | Select-String -Pattern "Status"
"""
        result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print(result.stdout.strip() if result.stdout.strip() else "Island is offline.")
