#!/usr/bin/env python
import os
import paramiko
import socket 
import datetime
import smtplib
import logging
import logging.handlers
import subprocess
import calendar
import OpenSSL
import ssl
import time
import ssl
from urlparse import urlparse
import urllib2, json
from email.mime.text import MIMEText


#Servers where the script going to spread letsencript certificate.
#Example for linux servers
#linux={'server1':{'distro':'centos 6.0','site':'https://example.com' } }
linux={IP_ADDRESS:{'distro':DISTRO,'site':URL } }


#Example for windows servers
#windows={'server1':{'site':'Default Web Site', 'hostname':'hostname.domain.com'}}
windows={'IP_ADDRESS':{'site':'Default Web Site', 'hostname':'IP_ADDRESS'}}


#Email and logs constants
#Example of SMTP adrress   = ["smtp.example.com"]
SMTP_HOST = SMTP_ADDRESS_SERVER
LOG_FILE = "/root/scripts.letsencrypt/logs/certificado.log"
#Example of email adrress EMAILS  = ["user@example.com"]
EMAILS  = [EMAIL_ADDRESS]

#Funcion inicio Logs
def init_logger():
	global logger

	# create logger
	logger = logging.getLogger(__name__)

	# create file handler
	print("Creating handler...")
	fh = logging.FileHandler(LOG_FILE)
	#fh = logging.StreamHandler(LOG_FILE)

	# create formatter
	print("Creating formatter...")
	formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

	# add formatter to fh
	print("Adding formatter to handler...")
	fh.setFormatter(formatter)

	# add fh to logger
	print("Adding handler to logger...")
	logger.addHandler(fh)	
	
	logger.setLevel('INFO')


# Envia correo electronico		
def send_email(msgbody, subject, emails):

	print("\tEnviando Email...\n")
	
	toaddrs = emails
	fromaddr = FROM_EMAIL_ADDRESS

	# Add the From: and To: headers at the start!
	msg_headers = "From: Renewal Script Certification<FROM_EMAIL_ADDRESS>\r\n"
	msg_headers = msg_headers + "Subject: " + subject + "\r\n"
	sendmsg = msg_headers + msgbody

	server = smtplib.SMTP(SMTP_HOST)
	server.set_debuglevel(0)
	server.sendmail(fromaddr, toaddrs, sendmsg)
	server.quit()

#### Renewal Certification Function ####
def renewal():

        try:
                print ("Renewing......")
                
                cmd= "certbot certonly  --manual --manual-auth-hook authenticator.sh --manual-cleanup-hook cleanup.sh --server https://acme-v02.api.letsencrypt.org/directory --manual-public-ip-logging-ok --config-dir   " +  linux_folder + "  --email postmaster@domain --agree-tos --non-interactive -d"+  DOMAIN_CERTIFICATE

                os.system(cmd)
                logger.info("The file has renovated and it saved in the folder " + linux_folder)
        except os.error as e:
                print ("An error has found at the running script: "  +  str(e))
                logger.warning("An error has found at the running script: " + str(e))
                
        except Exception as e:
                print ("The renewal command has failed")
                logger.warning("The renewal command has failedr with the next error: " + str(e) )
                

## Function for spread the certificates and restart the services at Linux servers
def spread_linux(linux):
    
    host_port=22021
    username='root'     
    local_path= linux_folder + 'archive/FOLDER_WHERE_YOU_WANT_TO_SAVED_CERTIFICATE/' + "*"
    remote_path='/etc/letsencrypt/archive/FOLDER_WHERE_YOU_WANT_TO_SAVED_CERTIFICATE/'
    
    for s in  linux:
        #Dovecot and postfix service    
        if s == "POSTFIX_SERVER":
                        command= 'cp  ' + local_path + "   "  + remote_path
                        os.system(command)
                        logger.info("copying  certificate to destiny folder in  POSTFIX_SERVER:  " ) 
                        command="systemctl  restart dovecot"
                        os.system(command)
                        logger.info("Restarting dovecot service in  POSTFIX_SERVER " )
                        command= "systemctl  restart postfix"
                        os.system(command)
                        logger.info("Restarting dovecot service in  POSTFIX_SERVER"  )
        else:
                try:
                        ##Transfiriendo archivos de certificado a servidor destino
                        print ("transferring certificate to:" +  s)
                        
                        command_scp= "scp  -P  " + str(host_port) + "  -r   " + local_path + "  " + username +"@"+ s + ":" + remote_path
                        #print command_scp
                        os.system(command_scp)
                        logger.info("transferring certificate to destiny service in :  " + str(s) )

                        ### Create ssh client
                        ssh=paramiko.SSHClient()
                        ### Automatically add the host to varified host file
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        ### Make a connection
                        ssh.connect(hostname=socket.gethostbyname(s), port=host_port, username=username)
                       
                        ##Restart the service
                        print ("Restarting services..." )
                        ### Choose the distro correspond to server
                        if linux[s]['distro'] == "debian":
                                print ("distro: ", linux[s]['distro'])
                                command="service  apache2 reload"
                                stdin, stdout, stderr = ssh.exec_command(command)
                                print (stdout.read())
                                logger.info("Restarting apache2 service in server: " + str(s)  )

                        if linux[s]['distro'] == "centos 6.0":
                                print ("distro: ", linux[s]['distro'])
                                command="/etc/init.d/httpd restart"
                                stdin, stdout, stderr = ssh.exec_command(command)
                                print (stdout.read())
                                logger.info("Restarting apache2 service in server: " + str(s) )
                        
                        else:   
                                print ("distro: ", linux[s]['distro'])
                                command="systemctl  restart httpd"
                                stdin, stdout, stderr = ssh.exec_command(command)
                                print (stdout.read())
                                logger.info("Restarting apache2 service in server:  " + str(s) )
                                print ("Restarting services:  " + s  )
                        
                        ssh.close()

                except os.error as e:
                        print ("It have found the next error in the exctution of scp command: " + str(e))
                        logger.warning(e)
                        

                except paramiko.ssh_exception.AuthenticationException:
                        print ("Failed in the authentication please check the credentials : %s")
                        

                except paramiko.SSHException as sshException:
                        print  ("IT's not possible of establish ssh connection : %s" % sshException)
                        logger.warning(sshException)
                        

                except Exception as e:
                        print ("error found  " + str(e))
                        

## Funtion for spread the certificate  and restart the services at  Windows servers.
def spread_windows(windows):

        host_port=22021
        user=ADMIN_USER   
        local_path=windows_folder + "/*"
        remote_path= "C:/temp"

        for s in  windows:
                try:
                        ## Transferring  file certificate to destiny folder
                        print ("transferring to: "+ s )

                       
                        command_ssl='openssl pkcs12 -export -out  ' + windows_folder + 'certificateforwindows.pfx -inkey  ' + linux_folder_live + 'privkey.pem -in  ' + linux_folder_live + 'cert.pem -certfile  ' + linux_folder_live  + 'fullchain.pem  -word : '
                        command_scp= "scp  -P " + str(host_port) + "  -r   " + local_path + "  adminservicios@"+ s + ":" + '"{}"'.format(remote_path)
                        
                        os.system(command_ssl)
                        os.system(command_scp)

                        logger.info("Transferring  file certificate to destiny folder in : " + str(s) ) + "server"

                        ### Create ssh client
                        ssh=paramiko.SSHClient()

                        ### Automatically add the host to varified host file
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        ### Make a connection
                        ssh.connect(hostname=socket.gethostbyname(s), port=host_port, username=user)       

                        ##Viculando certificados a las servidores web
                        print ("Installing certificates...")
                        
                        #Deleted old certificates
                        command='powershell.exe -Command  ' + '"&     {Get-ChildItem cert:\LocalMachine\My | where-object { $_.Subject -like '+ "'*DOMAIN*'" + ' }  | Sort-Object | Select-Object -First 1 | Remove-Item}"'
                        print (command)
                        stdin, stdout, stderr = ssh.exec_command(command)
                        logger.info("Deleting old certificate from server: " + s  )
                        logger.info(str(stdout.read()))

                        #Import certificate
                        command="powershell.exe    -Command  "+ '"& {certutil -f -p  -importpfx  ' + remote_path + "/certificateforwindows.pfx"  + '}"'
                        stdin, stdout, stderr = ssh.exec_command(command)
                        print (command)
                        logger.info("Importando certificado en servidor destino: " + str(s)  )
                        logger.info(str(stdout.read()))

                        #Get the Certificate Hash or 'Thumbprint'
                        command= "powershell.exe    -Command  " + '"&   {(Get-ChildItem cert:\LocalMachine\My | where-object { $_.Subject -like' + "'*DOMAIN*'" + '} | Sort-Object | Select-Object -First 1).Thumbprint}"'
                        time.sleep(2)
                        print (command)
                        stdin, stdout, stderr = ssh.exec_command(command)
                        cert=stdout.read()
                        logger.info("Obteniendo valor de cert: " + cert )
                        logger.info(str(stdout.read()))


                        #Bind the certificate to an IP Address and Port
                        command="powershell.exe    -Command  " + '"&   {[guid]::NewGuid().ToString('B')}"'
                        stdin, stdout, stderr = ssh.exec_command(command)
                        time.sleep(2)
                        guid=stdout.read()
                        guid=str.join(" ", guid.splitlines())
                        logger.info("Obteniendo valor de guid:" + guid + "  " + str(stdout.read()))

                        command='powershell.exe   -Command  ' + '"&  {netsh http delete sslcert hostnameport=' + windows[s]['hostname'] + ':443' + '}"'
                        stdin, stdout, stderr = ssh.exec_command(command)
                        time.sleep(2)
                        print (command)
                        print (stdout.read())
                        logger.info("Deleting old certificates in destiny folder in server: " + str(s))
                        logger.info(str(stdout.read()))

                        command='powershell.exe   -Command  ' + '"&  {netsh http add sslcert hostnameport=' + windows[s]['hostname'] + ':443'  + '  certhash=' + cert + 'certstorename=MY appid=' + "'{" + guid + "}'" + '}"' 
                        command= str.join(" ", command.splitlines())
                        print (command)
                        stdin, stdout, stderr = ssh.exec_command(command)
                        time.sleep(2)
                        logger.info("Se bindeo el certificado en el servidor destino: " +  str(s)  )
                        logger.info(str(stdout.read()))
                         
                        #Close ssh conection
                        ssh.close()
                except paramiko.ssh_exception.AuthenticationException:
                        print ("Failed the authentication please check your credentials  : %s")
                        logger.warning("Error found in credentials process")
                        
                except paramiko.SSHException as sshException:
                         print ("It's imposible establisg ssh conection : %s" % sshException)
                         logger.warning("Failed ssh conection")
                         

                except Exception as e:
                        print ("An error has ocurred" + str(e))
                        logger.warning("")
                        

# Function used to report by email.
def expiration_date(linux):

        print ("Iniciando proceso fecha de expiracion...")

        informe=open("/root/scripts.letsencrypt/dates.txt", 'w+')
        informe.write("Sites \t\t\t" + "Expiration date" + "\n" )
        for s in linux:
                try:
                        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

                        context = ssl.create_default_context()
                        conn = context.wrap_socket(
                                socket.socket(socket.AF_INET),
                                server_hostname=linux[s]['site'],
                        )
                        # 3 second timeout because Lambda has runtime limitations
                        if s == "POSTFIX_SERVER":
                                myCmd = os.popen('openssl s_client -servername server_name.domain -connect imap.domain:995  2>/dev/null | openssl x509 -noout -enddate').read()
                                command =  myCmd.split("=",1)[1]
                                print (s)
                                fecha = datetime.datetime.strptime(command.replace('\n', ''), ssl_date_fmt)
                                print (fecha)
                                informe.write(linux[s]['site'] + " = " +"  " + str(fecha) + "\n")

                                
                        else:
                                conn.connect((s, 443))
                                ssl_info = conn.getpeercert()
                                print s
                                fecha = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
                                print   fecha
                                informe.write(linux[s]['site'] + " = " +"  " + str(fecha) + "\n")
                except Exception, e:
                        print "An error has found" + str(e)
                        logger.warning("An error has found in informed in the server: " + (s) )
                        

        for s in windows:
                try:
                        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

                        context = ssl.create_default_context()
                        conn = context.wrap_socket(
                                socket.socket(socket.AF_INET),
                                server_hostname=windows[s]['hostname'],
                        )
                        # 3 second timeout because Lambda has runtime limitations
                        conn.connect((s, 443))
                        ssl_info = conn.getpeercert()
                        print s
                        fecha = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
                        print   fecha
                        informe.write(windows[s]['site'] + " = " +"  " + str(fecha) + "\n")
                except Exception, e:
                        print "An error has found" + str(e)
                        logger.warning("An error has found: " + str(s))
                        

        informe.close()

        fp = open("/root/scripts.letsencrypt/dates.txt", 'rb')
        # Create a text/plain message
        msg = MIMEText(fp.read())
        fp.close()
     
        send_email(msg.as_string(), "Notification report: " + time.strftime("[%d %b %Y]", time.localtime()) , EMAILS)         

if __name__ == "__main__":
	
        global windows_folder
        global linux_folder
        
        print "Creating folders........... \n"

        now = datetime.datetime.now()
        today = str(now.date())
        windows_folder= "/etc/letsencrypt/{0}/{1}-{2}/{3}-{4}/windows/".format(str(now.year),str(now.month),str(calendar.month_name[now.month]),str(now.day),now.strftime("%A"))
        linux_folder= "/etc/letsencrypt/{0}/{1}-{2}/{3}-{4}/linux/".format(str(now.year),str(now.month),str(calendar.month_name[now.month]),str(now.day),now.strftime("%A"))
        linux_folder_live= "/etc/letsencrypt/{0}/{1}-{2}/{3}-{4}/linux/live/DOMAIN/".format(str(now.year),str(now.month),str(calendar.month_name[now.month]),str(now.day),now.strftime("%A"))
        os.makedirs(windows_folder)    
        os.makedirs(linux_folder)  

        init_logger()
        
        logger.info("Starting script....")

        renewal()
        logger.info("Allocating certificate in linux servers....." )
        spread_linux(linux)
        logger.info("Allocating certificate in windows servers......")
        spread_windows(windows)
        logger.info("Sending email......")

        # Build a final report and it send it by mail 
        expiration_date(linux)
