#!/usr/bin/python

from operator import eq
from scapy.all import *
import sys

#!!!!!hangul patch nono sorry!!!!!/english jal mot ham/(window)copy and (linux)paste possible


'''
    출력, 사용은 16진수 %02x
	ethernet
	data[0] ~ data[13] : ethernet 정보 (14byte)

	ip
	data[14] : 상위 4bit : version - 저장X
	하위 4bit : ip 헤더 길이 정보 - ipheaderlen 변수에 저장 /*ipheaderlen = data[14.5]*4*/
    data[23] : 프로토콜 타입 : ICMP - 1, TCP - 6, UDP - 17
	data[25] ~ data[28] : 발신지 ip주소
	data[29] ~ data[33] : 수신지 ip주소
'''


class filterItem :
    #필터 구조체 : 프로토콜타입/ip주소/포트번호
    protocolType = ''
    portNumber =''
    ipAddr = ''

protocols = {1:'icmp', 6:'tcp', 17:'udp', 53:'dns', 80:'http'}
curFilter=filterItem() #필터 전역변수 선언
curSelect = 0 #Display() while var
count=1 #==index

def sniffing():
    print("Sniffing Start")
    f=filter_string()
    pcap_file = sniff(prn=showPacket, timeout=100, filter=str(f))
    print(f)
    #pcapfile=sniff(prn=showPacket, timeout=int(sniffing_time))
    print("Finish Capture Packet")

    if count == 1:
            print("No Packet")
            sys.exit()
    else:
        print("Total Packet: %s" %(count-1))
        '''
        #origin/store code
        file_name = input("Enter File Name: ")
        wrpcap(str(file_name), pcap_file)
        '''


def showPacket(packet):
    # [count] protocol|srcIP -> dstIP|srcPort -> dstPort|flag|length|ttl ...
    global count
    # IP packet[0][1]==packet[IP]
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    proto = packet[0][1].proto
    ttl = packet[0][1].ttl
    length = packet[0][1].len

    '''
    packet[0][2]==packet[ICMP/TCP/UDP]
    packet[ICMP/TCP/UDP] here 파이참에선 빨간 줄 떠서 안 돌아가는데 터미널에선 정상실행돼요
    >>> sudo python3 pcapture.py
    '''

    if proto in protocols:
        # ICMP
        if proto == 1:
            message_type = packet[ICMP].type
            code = packet[ICMP].code

            print("[%d] | %s | ip: %s -> %s | ttl:%s | type:%s | code:%s" % (
                count, protocols[proto].upper(), src_ip, dst_ip, ttl, message_type, code))


        # TCP
        if proto == 6:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].dport
            ack = packet[TCP].ack
            flag = packet[TCP].flags

            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | ttl:%s | len:%s | seq:%s | ack:%s | flag:%s " % (
            count, protocols[proto].upper(), src_ip, dst_ip, sport, dport, ttl, length, seq, ack, flag))


        # UDP
        if proto == 17:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            udp_length = packet[UDP].len

            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | ttl:%s | len:%s " % (
                count, protocols[proto].upper(), src_ip, dst_ip, sport, dport, ttl, udp_length))

        #dns   !!!!!!!HELP!!!!!!!
        if proto == 53:
            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | ttl:%s | len:%s " % (
                count, protocols[proto].upper(), src_ip, dst_ip, ttl, ttl, ttl, ttl))


        #http    !!!!!!!HELP!!!!!!!
        if proto == 80:
            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | ttl:%s | len:%s " % (
                count, protocols[proto].upper(), src_ip, dst_ip, ttl, ttl, ttl, ttl))


        count += 1


def filter_string():
    #sniff filter paramenter function
    global curFilter
    tmp = ''
    if(not eq(curFilter.protocolType,'')):
        tmp = tmp  +str(curFilter.protocolType) + " and "
    if(not eq(curFilter.portNumber,'')):
        tmp = tmp + "port " + str(curFilter.portNumber) + " and "
    if(not eq(curFilter.ipAddr,'')):
        tmp = tmp + "host " + str(curFilter.ipAddr)

    if (tmp.endswith(" and ")):
        tmp = tmp[0:len(tmp)-5]

    return tmp



def setFilter(initialize = 0):
    global curFilter
    if(initialize == 1):
        print("---------------필터를 초기화 합니다.----------------")
        curFilter=filterItem()

    else :
        print("---------------------필터 설정----------------------\n"
              "검색하고 싶은 항목의 정보를 입력하세요.\n"
              "검색에서 제외할 항목은 공백을 입력해주세요.\n"
              "---------------------------------------------------")
        curFilter.protocolType = input("프로토콜 타입을 입력하세요 >>> ")
        curFilter.portNumber = input("포트 번호를 입력하세요 >>>")
        curFilter.ipAddr = input("IP 주소를 입력하세요 >>> ")


def printFilterInfo() :
    global curFilter
    print("-------------------------필터 정보-------------------------")
    print("Protocol Type : ", curFilter.protocolType)
    print("Port Number : ", curFilter.portNumber)
    print("Ip Address : ", curFilter.ipAddr)


def Display():
    global curSelect
    print("\n\n--------------------KPU 패킷 캡쳐 프로그램---------------------")
    print("1) 필터 설정하기\n"
          "2) 필터 정보 확인하기\n"
          "3) 필터 초기화 하기\n"
          "4) 패킷 수집하기\n"
          "9) 프로그램 종료하기")
    print("------------------------------------------------------------")
    curSelect = input("번호를 입력하세요 >>> ")
    print("\n")




#-----------------------MAIN-----------------------

while (1):
    Display()

    if (eq(curSelect, '1')):
        #필터9 설정
        setFilter()
        pass

    elif (eq(curSelect, '2')):
        #필터 정보 확인
        printFilterInfo()
        pass

    elif (eq(curSelect, '3')):
        #필터 초기화 //필터 설정 함수(1) -> 초기화됨
        setFilter(1)
        pass

    elif (eq(curSelect, '4')):
        #패킷 출력
        sniffing()

    elif (eq(curSelect, '9')):
        #프로그램 종료
        print("프로그램을 종료합니다.")
        quit()
    else:
        print("다시 입력해 주세요.")
        pass

