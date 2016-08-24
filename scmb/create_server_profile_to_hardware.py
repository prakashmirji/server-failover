import os
import time
import logging
import csv
import hpOneView as hpov
import sys
import json
import traceback

global dat1,tim1,fwuri,pwd,srv
dat1 = time.strftime("%d:%m:%Y")
tim1=time.strftime("%H:%M:%S")
pwd=os.getcwd()


def acceptEULA(con):
    # See if we need to accept the EULA before we try to log in
    con.get_eula_status()
    try:
        if con.get_eula_status() is True:
            print('EULA display needed')
            con.set_eula('no')
    except Exception as e:
        print('EXCEPTION:')
        print(e)

def login(con, credential):
    # Login with given credentials
    try:
        con.login(credential)
    except Exception as e :
        print('Login failed')

def logout(con):
    # Logout
    try:
        con.logout()
    except Exception as e :
        print('Logout failed')


def create_server_profile_to_available_server(con,spuri, serverHardwareList):
    global server_profile_uri
    #server_profile_uri=spuri
    #GET operation for server profile uri
    response = con.get(spuri)
    server_profile_name=response['name']
    file_name=pwd+"/json/"+server_profile_name+".json"
    with open(file_name, 'w') as f:
        json.dump(response, f)
    server_profile_name=response['name']
    server_hardware_uri = response['serverHardwareUri']
    logging.info(" "+dat1+" "+tim1+ server_hardware_uri)
    flag = 0
    result =  apply_server_profile(con,spuri,response,server_hardware_uri, serverHardwareList)                 
    while((result != 'Success') and (flag !=2)):
        logging.info(" "+dat1+" "+tim1+" Error in Server Profile creation")
        print("Error in Server Profile creation!  Creating Server Profile for next available Server!")
        logging.info(" "+dat1+" "+tim1+"Error in Server Profile creation!  Creating Server Profile for next available Server!")
        result =  apply_server_profile(con,spuri,response,server_hardware_uri, serverHardwareList)
        flag = flag+1
    if(flag == 2):
        print("Error in Server Profile creation!")
        logging.info(" "+dat1+" "+tim1+"Error in Server Profile creation!")
 

def apply_server_profile(con,spuri,profile_response,hardware_uri, serverHardwareList):
    #function to apply server profile on the availablle server
    server_profile_name=profile_response['name']
    server_uri='/rest/server-hardware?filter=\"state=\'NoProfileApplied\'\"'
    #GET operation to get all the servers in the OV 
    available_servers_response = con.get(server_uri)
    if available_servers_response['count'] == 0:
        print("no bare servers available!! ")
        logging.info(" "+dat1+" "+tim1+" "+"no bare servers available!!")
    else:
        count = 0
        for server in available_servers_response['members']:
            available_server_hardware_uri = server['uri']
            if((available_server_hardware_uri not in serverHardwareList) and (health_of_server(con,available_server_hardware_uri))  and  (checkNicStatus(con, available_server_hardware_uri)) and (hardware_uri != available_server_hardware_uri )):
                available_server_hardware_type_uri = server['serverHardwareTypeUri']
                available_server_hardware_powerstate = server['powerState']
                server_hardware_uri = profile_response['serverHardwareUri']
                server_hardware_type_uri=profile_response['serverHardwareTypeUri']
                available_server_hardware_enclosuregrp = server['serverGroupUri']
                hardware_response = con.get(server_hardware_uri)
                hardware_power = hardware_response['powerState']
                if((available_server_hardware_type_uri == server_hardware_type_uri) and (server['name']!= 'none')):
                    print("Hardware Health Status"+" : "+ "OK")
                    logging.info(" "+dat1+" "+tim1+" Health Status : OK")
                    print("Nic Status"+" : "+ "Good")
                    logging.info(" "+dat1+" "+tim1+" Nic Status : Good")
                    print("Hardware Matched : " + server['name'] )
                    logging.info(" "+dat1+" "+tim1+"Hardware Matched : " + server['name'] )
                    serverHardwareList.append(available_server_hardware_uri)
                    if(hardware_power == 'On'):
                        change_power_state(con,server_hardware_uri,'Off')
                    if(available_server_hardware_powerstate == "On"):
                        change_power_state(con,available_server_hardware_uri,'Off')
                    profile_response['serverHardwareUri']=available_server_hardware_uri
                    profile_response['name']=server_profile_name
                    profile_response['enclosureGroupUri']=available_server_hardware_enclosuregrp 
                    if( 'enclosureUri' in profile_response):
                        del profile_response['enclosureUri']
                    if( 'enclosureBay' in profile_response):
                        del profile_response['enclosureBay']
                    print("Creating Server Profile :"+ server_profile_name )
                    logging.info(" "+dat1+" "+tim1+" "+"Creating Server Profile :"+ server_profile_name )
                    try:
                        resp,ret=con.put(spuri,profile_response)
                        print("Task: %s" %(resp['uri']))
                        task_uri=resp['uri']
                        try:
                            act=hpov.activity(con)
                            res=act.wait4task(resp,tout=3000)
                            if (((res['taskState']=="Warning") or (res['taskState']=="Critical")) and (res['stateReason']=="Completed")):
                               returnFlag = 'Failure'
                               count = 1
                            elif (res['stateReason']=="Completed"):
                                print("Profile Created : "+ server_profile_name)
                                logging.info(" "+dat1+" "+tim1+" Profile Created : "+ server_profile_name)
                                change_power_state(con,available_server_hardware_uri,'On')
                                count = 1
                                returnFlag = 'Success'
                            else :  
                                returnFlag = 'Failure'                    
                                count = 1 
                        except:
                            print("Profile creation timed out")
                            logging.info(" "+dat1+" "+tim1+" "+"Profile creation timed out!")
                    except:
                        print("Issue in create server profile")
                        logging.info(" "+dat1+" "+tim1+" "+"Issue in create server profile"+traceback.format_exc())
                        returnFlag = 'Failure'
                        count = 1
                    #logging.info(" "+dat1+" "+tim1+" "+"Before Removed :Now ServerHardwareList has: "+ str(serverHardwareList))
                    serverHardwareList.remove(available_server_hardware_uri) 
                    #logging.info(" "+dat1+" "+tim1+" "+"After Removed :Now ServerHardwareList has: "+ str(serverHardwareList)) 
                   
                if(count==1):
                    break
        if(count==0):
            print("no available servers for particular hardware type!! ")
            logging.info(" "+dat1+" "+tim1+" "+"no available servers for particular hardware type!!")      
            return  'Success'
        else:
            return returnFlag 
  

def change_power_state(con,shuri,state):
    #Create PUT request JSON body
    body={
        "powerControl":"PressAndHold",
        "powerState": state
        }
    if(state == 'On'):
         body={
             "powerControl":"MomentaryPress",
             "powerState": state
              }
    auri=shuri+"/powerState"
    print("Powering "+state+" The Server") 
    logging.info(" "+dat1+" "+tim1+" Powering "+state+" the Server")
    try:
        response,ret = con.put(auri,body)
        act=hpov.activity(con)
        taskStatus=act.wait4task(response,tout=500)
        if taskStatus['taskState']=="Completed":
            print("Server Powered "+state)
            logging.info(" "+dat1+" "+tim1+" Server Powered "+state)
    except:
        logging.info(" "+dat1+" "+tim1+"_"+"Error in powering on server")


def health_of_server(con,hardwareuri):
    if (hardwareuri != None):
        response = con.get(hardwareuri)
        server_status = response['status']
        if (server_status == 'OK'):
            return True
        return False
    else: 
        return False

def checkNicStatus(con, serverHardwareUri):
    serverHardware = con.get(serverHardwareUri)
    if ( serverHardware['locationUri'] ):
        enclosure = con.get(serverHardware['locationUri'])
        if( enclosure['interconnectBays'] and enclosure['interconnectBays'][0] and enclosure['interconnectBays'][0]['logicalInterconnectUri']):
            logicalInterconnect = con.get(enclosure['interconnectBays'][0]['logicalInterconnectUri'])
            if(logicalInterconnect['status']):
                if(logicalInterconnect['status'] == 'OK'):
                    return True
                else:
                    return False


def create_server_profile_copy(hostip,user,password,uri, serverProfilesList, serverHardwareList):

    #connect to the appliance
    logging.info(" "+dat1+" "+tim1+ hostip)
    credential = {'userName': user, 'password': password}
    con = hpov.connection(hostip)
    login(con, credential)
    acceptEULA(con)
    global act
    act = hpov.activity(con)
    try:
        create_server_profile_to_available_server(con,uri, serverHardwareList)
    except:
        logging.info(" "+dat1+" "+tim1+" "+"Exited from create_server_profile_to_available_server")
        print("Exited from create_server_profile_to_available_server: "+traceback.format_exc()) 
    serverProfilesList.remove(uri)    
    logging.info(" "+dat1+" "+tim1+" "+"Removed "+uri+" Now ServerProfileList has: "+ str(serverProfilesList))
    logout(con)




