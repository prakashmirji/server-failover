import pika, ssl
import sys, os
from hpOneView import *
from pika.credentials import ExternalCredentials
import json
import logging
import create_server_profile_to_hardware as csp
import argparse
from threading import Thread,current_thread
import time
import traceback


pwd=os.getcwd()

serverProfilesList=[]
serverHardwareList=[]
global host, user, passwd, threads,dat1,tim1,dat,  serverProfilesList, serverHardwareList
threads=[]
dat1 = time.strftime("%d:%m:%Y")
tim1=time.strftime("%H:%M:%S")
dat = time.strftime("%d-%m-%Y")

###############################################
# Callback function that handles messages
def callback(ch, method, properties, body):
        if isinstance(body, str):
                msg = json.loads(body)
        elif str(type(body)) == "<class 'bytes'>":
                msg = json.loads(body.decode('ascii'))
        elif str(type(body)) == "<type 'unicode'>":
                msg = json.loads(body.decode("utf-8"))
        timestamp = msg['timestamp']
        resource = msg['resource']
        changeType = msg['changeType']
        logging.debug(" "+dat1+" "+tim1+" "+"Testing ServerProfile list Value: "+str(serverProfilesList))

        if(('alertState' in resource) and ('severity' in resource)):
               if(('/rest/server-profiles' in resource['resourceUri']) and (('Active' == resource['alertState']) or ('Locked' == resource['alertState'])) and (('Critical' == resource['severity']) or ('Warning' ==  resource['severity'])) and (resource['resourceUri'] not in serverProfilesList)):
                        resourceUri=resource['resourceUri']
                        serverProfilesList.append(resourceUri)
                        logging.debug(" "+dat1+" "+tim1+" "+resourceUri)
                        print ("Server Profile has entered into Critical State!!!")
                        logging.info(" "+dat1+" "+tim1+"Server Profile has entered into Critical State!")
                        try:
                               time.sleep(60)
                               t=Thread(target=csp.create_server_profile_copy, args=(host, user, passwd, resourceUri, serverProfilesList, serverHardwareList))
                               threads.append(t)
                               t.start()
                        except:
                               print("Failed in copy server profile") 
			

def login(con, credential):
        # Login with givin credentials
        try:
                con.login(credential)
        except:
                print('Login failed')

def logout(con):
        # Logout 
        try:
                con.logout()
        except:
                print('Logout failed')



def acceptEULA(con):
        # See if we need to accept the EULA before we try to log in
        con.get_eula_status()
        try:
                if con.get_eula_status() is True:
                        con.set_eula('no')
        except Exception as e:
                print('EXCEPTION:')
                print(e)


def getCertCa(sec):
        cert = sec.get_cert_ca()
        ca = open('caroot.pem', 'w+')
        ca.write(cert)
        ca.close()


def genRabbitCa(sec):
       sec.gen_rabbitmq_internal_signed_ca()


def getRabbitKp(sec):
        cert = sec.get_rabbitmq_kp()
        ca = open('client.pem', 'w+')
        ca.write(cert['base64SSLCertData'])
        ca.close()
        ca = open('key.pem', 'w+')
        ca.write(cert['base64SSLKeyData'])
        ca.close()

def recv(host, route):

        # Pem Files needed, be sure to replace the \n returned from the APIs with CR/LF
        # caroot.pem - the CA Root certificate - GET /rest/certificates/ca
        # client.pem, first POST /rest/certificates/client/rabbitmq Request body:
        #    {"type":"RabbitMqClientCertV2","commonName":"default"}
        # GET /rest/certificates/client/rabbitmq/keypair/default
        # client.pem is the key with -----BEGIN CERTIFICATE-----
        # key.pem is the key with -----BEGIN RSA PRIVATE KEY-----

        # Setup our ssl options
        ssl_options = ({"ca_certs": "caroot.pem",
                "certfile": "client.pem",
                "keyfile": "key.pem",
                "cert_reqs": ssl.CERT_REQUIRED,
                "ssl_version": ssl.PROTOCOL_TLSv1_1,
                "server_side": False})

        # Connect to RabbitMQ
        print ("Connecting to %s:5671, to change use --host hostName " %(host))
        connection= None
        try:
            connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                            host, 5671, credentials=ExternalCredentials(),
                            ssl=True, ssl_options=ssl_options))
        except:
            connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                            host, 5671, credentials=ExternalCredentials(),
                            ssl=True, ssl_options=ssl_options))


        # Create and bind to queue
        EXCHANGE_NAME = "scmb"
        ROUTING_KEY = "scmb.#"
        if('scmb' in route):
                ROUTING_KEY = route

        channel = connection.channel()
        result = channel.queue_declare()
        queue_name = result.method.queue
        print("ROUTING KEY: %s" %(ROUTING_KEY))

        channel.queue_bind(exchange=EXCHANGE_NAME, queue=queue_name, routing_key=ROUTING_KEY)

        channel.basic_consume(callback,
                  queue=queue_name,
                  no_ack=True)

        # Start listening for messages
        channel.start_consuming()

parser = argparse.ArgumentParser(add_help=True, description='Usage')
parser.add_argument('-a', '--appliance', dest='host',default='10.54.31.213', required=False,
                   help='HPE OneView Appliance hostname or IP')
parser.add_argument('-u', '--user', dest='user', required=False,
                   default='Administrator', help='HPE OneView Username')
parser.add_argument('-p', '--pass', dest='passwd',default='password', required=False,
                   help='HPE OneView Password')
parser.add_argument('-r', '--route', dest='route', required=False,
                   default='scmb.alerts.#', help='AMQP Routing Key')
args = parser.parse_args()
credential = {'userName': args.user, 'password': args.passwd}
user = args.user
passwd = args.passwd
host = args.host
con = connection(args.host)
sec = security(con)

login(con, credential)
acceptEULA(con)

logfilepath = pwd + os.sep + 'SCMB_LogFile.log'
logging.basicConfig(filename=logfilepath, filemode="a", level=logging.INFO, format="%(threadName)s:%(message)s")
logging.info(" "+dat1+" "+tim1+"BEGIN : SCMB Script!!!") 


# Generate the RabbitMQ keypair (only needs to be done one time)
try:
    genRabbitCa(sec)
except:
    print("Certificate already existing")
time.sleep(15)

try:
    getCertCa(sec)
    getRabbitKp(sec)
except:
    print("Error in certificate download"+traceback.format_exc())
time.sleep(15)

logout(con)
recv(args.host, args.route)

