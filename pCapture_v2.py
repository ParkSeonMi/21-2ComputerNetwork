#!/usr/bin/python
#2021.12.07 수정

from operator import eq
from scapy.all import *
import sys


'''
	패킷 구조
	ethernet
	data[0] ~ data[13] : ethernet 정보 (14byte)

	ip
	data[14] : 상위 4bit : version - 저장X
	하위 4bit : ip 헤더 길이 정보 - ipheaderlen 변수에 저장 /*ipheaderlen = data[14.5]*4*/
    data[23] : 프로토콜 타입 : ICMP - 1, TCP - 6, UDP - 17
	data[25] ~ data[28] : 발신지 ip주소
	data[29] ~ data[33] : 수신지 ip주소
	
	tcp - http
	udp - dns
'''
	
'''
scapy 라이브러리 내 메서드 정보
>>> ls(IP())
version    : BitField  (4 bits)                  = 4               ('4')
ihl        : BitField  (4 bits)                  = None            ('None')
tos        : XByteField                          = 0               ('0')
len        : ShortField                          = None            ('None')
id         : ShortField                          = 1               ('1')
flags      : FlagsField                          = <Flag 0 ()>     ('<Flag 0 ()>')
frag       : BitField  (13 bits)                 = 0               ('0')
ttl        : ByteField                           = 64              ('64')
proto      : ByteEnumField                       = 0               ('0')
chksum     : XShortField                         = None            ('None')
src        : SourceIPField                       = '127.0.0.1'     ('None')
dst        : DestIPField                         = '127.0.0.1'     ('None')
options    : PacketListField                     = []              ('[]')


>>> ls(TCP())
sport      : ShortEnumField                      = 20              ('20')
dport      : ShortEnumField                      = 80              ('80')
seq        : IntField                            = 0               ('0')
ack        : IntField                            = 0               ('0')
dataofs    : BitField  (4 bits)                  = None            ('None')
reserved   : BitField  (3 bits)                  = 0               ('0')
flags      : FlagsField                          = <Flag 2 (S)>    ('<Flag 2 (S)>')
window     : ShortField                          = 8192            ('8192')
chksum     : XShortField                         = None            ('None')
urgptr     : ShortField                          = 0               ('0')
options    : TCPOptionsField                     = []              ("b''")

>>> ls(UDP())
sport      : ShortEnumField                      = 53              ('53')
dport      : ShortEnumField                      = 53              ('53')
len        : ShortField                          = None            ('None')
chksum     : XShortField                         = None            ('None')

	
>>> ls(DNS())
length     : ShortField (Cond)                   = None            ('None')
id         : ShortField                          = 0               ('0')
qr         : BitField  (1 bit)                   = 0               ('0')
opcode     : BitEnumField                        = 0               ('0')
aa         : BitField  (1 bit)                   = 0               ('0')
tc         : BitField  (1 bit)                   = 0               ('0')
rd         : BitField  (1 bit)                   = 1               ('1')
ra         : BitField  (1 bit)                   = 0               ('0')
z          : BitField  (1 bit)                   = 0               ('0')
ad         : BitField  (1 bit)                   = 0               ('0')
cd         : BitField  (1 bit)                   = 0               ('0')
rcode      : BitEnumField                        = 0               ('0')
qdcount    : DNSRRCountField                     = 0               ('None')
ancount    : DNSRRCountField                     = 0               ('None')
nscount    : DNSRRCountField                     = 0               ('None')
arcount    : DNSRRCountField                     = 0               ('None')
qd         : DNSQRField                          = None            ('None')
an         : DNSRRField                          = None            ('None')
ns         : DNSRRField                          = None            ('None')
ar         : DNSRRField                          = None            ('None')

'''


class filterItem :
    #필터 구조체 : 프로토콜타입/ip주소/포트번호
    protocolType = ''
    portNumber =''
    ipAddr = ''


protocols = {1:'icmp', 6:'tcp', 17:'udp'}
curFilter=filterItem() #필터 전역변수 선언
curSelect = 0 #Display() while var
count=1 #index


def sniffing():
    print("Sniffing Start")
    f=filter_string()
    pcap_file = sniff(prn=showPacket, timeout=99999, filter=str(f)) #기본 시간 99999초로 설정
    print("Finish Capture Packet")

    if count == 1:
            print("No Packet")
            sys.exit()
    else:
        print("Total Packet: %s" %(count-1))

        
	
def showPacket(packet):
    # [count] protocol | srcIP -> dstIP | srcPort -> dstPort | flag | length | ttl ...
    global count
    # IP packet[0][1]==packet[IP]
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    proto = packet[0][1].proto
    ttl = packet[0][1].ttl
    length = packet[0][1].len
    #dns=packet[1][3]


    if proto in protocols:
        # ICMP
        if proto == 1:
            message_type = packet[ICMP].type
            code = packet[ICMP].code
            length=packet.len

            print("[%d] | %s | ip: %s -> %s | type:%s | code:%s | len:%s | ttl:%s" % (
                count, protocols[proto].upper(), src_ip, dst_ip, message_type, code, length, ttl))


        # TCP
        if proto == 6:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            flag = packet[TCP].flags
            length=packet.len
            dataofs=packet[TCP].dataofs

            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | seq:%s | ack:%s | flag:%s | ttl:%s | len:%s | dataofs:%s " % (
            count, protocols[proto].upper(), src_ip, dst_ip, sport, dport, seq, ack, flag, ttl, length, dataofs))


        # UDP
        if proto == 17:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if(dport == 53 or sport == 53):
            	temp_proto = 'DNS'
            else:
            	temp_proto = 'UDP'
            
            
            udp_length = packet[UDP].len
            length=packet.len #why terminal != wireshark? but it doesnt look important

            print("[%d] | %s | ip: %s -> %s | port: %s -> %s | ttl:%s | len:%s " % (
                count, temp_proto, src_ip, dst_ip, sport, dport, ttl, udp_length))


        count += 1



def filter_string():
    #sniff 필터 메세지 제작
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
    #sniff 함수에 필터 설정
    global curFilter
    if(initialize == 1):
        print("---------------필터를 초기화 합니다.----------------")
        curFilter=filterItem()

    else :
        print("---------------------필터 설정----------------------\n"
              "검색하고 싶은 항목의 정보를 입력하세요.\n"
              "검색에서 제외할 항목은 공백을 입력해주세요.\n"
              "-------------------------------------------------------")
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
    print("----------------------------------------------------------------------")
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
        print("ctrl+c를 누르면 패킷 캡쳐가 중지됩니다.")
        sniffing()

    elif (eq(curSelect, '9')):
        #프로그램 종료
        print("프로그램을 종료합니다.")
        quit()

    else:
        print("다시 입력해 주세요.")
        pass

