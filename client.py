import sys
import smtplib
#tls config rules can be bundled in ssl
import ssl

#setting minimum tls version and taking the arg
target_version = sys.argv[1] if len(sys.argv) > 1 else "1.2"

#need to set the context(rulebook) for client side as postfix handles the server side
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


#forces smtplib to use the tls version we specify for the client 
if target_version == "1.2":
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
elif target_version == "1.3":
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3



# need this because we have a bs hostname and it doesnot match the cert
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE 

#docker with postfix server running at 2525:25
server = smtplib.SMTP("localhost",2525)
#print(server.ehlo())


from_addr = "sender@test.local"
to_addr = "receiver@test.local"
message = """From: sender@test.local
To: receiver@test.local
Subject: TLS Test
This is a test email over STARTTLS.
"""

server.ehlo()
#server.starttls is default behaviour - highest mordern security available - automatically overrides to the most latest tls ver
# startTLS has a context rulebook if we dont pass anything it defaults to the best security practices.
server.starttls(context=context)
#after we get tls running smtp treats as fresh connection so need ehlo again
server.ehlo()
server.sendmail(from_addr,to_addr,message)
server.quit()

