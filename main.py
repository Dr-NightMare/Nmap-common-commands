import subprocess

def run_nmap(ip, command):
    command = command.replace("<ip>", ip)
    output = subprocess.run(command.split(), capture_output=True, text=True)
    print(output.stdout)

def main():
    ip = input("Enter the IP to scan: ")

    commands = [
        "sudo nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A <ip>",
        "sudo nmap -A -Pn -sV -p- -T5 <ip>",
        "sudo nmap -sC -Pn -sV -p- -T5 <ip>",
        "sudo nmap -sV -T4 -O -F --version-light <ip>",
        "sudo nmap -sV -p 22,80,443 --script=firewall-bypass <ip>",
        "sudo nmap -sS -sV -O -T4 -A -F <ip>",
        "sudo nmap -sS -T4 -Pn -n -p- <ip>",
        "sudo nmap -sS -T4 -O -F --version-light <ip>",
        "sudo nmap -sS -sU -T4 -p- -A -v --script=all <ip>",
        "sudo nmap --script ssl-heartbleed <ip>",
        "sudo nmap --script smb-vuln-* <ip>",
        "sudo nmap --script http-vuln-* <ip>",
        "sudo nmap --script dns-vuln-* <ip>",
        "sudo nmap --script=snmp-info <ip>",
        "sudo nmap -sV --version-intensity 5 -O <ip>",
    ]

    print("[+] Example commands:")
    for i, command in enumerate(commands):
        command = command.replace("<ip>", ip)
        print(f"{i+1}. {command}")

    choice = input("Enter the number of the command to run or 'else' to enter a custom command: ")
    if choice == "else":
        custom_command = input("Enter the custom nmap command: ")
        run_nmap(ip, custom_command)
    else:
        try:
            choice = int(choice)
            if choice >= 1 and choice <= len(commands):
                command = commands[choice-1]
                run_nmap(ip, command)
            else:
                print("Invalid")
        except ValueError:
            print("Invalid")

if __name__ == "__main__":
    main()
