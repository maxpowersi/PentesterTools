#!/bin/bash

while ${1+:} false
do
	case "$1" in
		debug)
			PS4='$LINENO: '
			set -x
			shift
		;;
		pad)
			pad=1
			shift
		;;
		csv)
			csv=1
			echo 'TARGET:PORT,SSL2,SSL3,TLS1.0,TLS1.1,SCKL,ExpRSA,ExpEDH,RC4,SDHEK,64bit,PFS,SWEET32,POODLE, Insec.Reneg.'
			shift
		;;
		*)
			if [ -f "$1" ] 
			then
				inputFile="$1"
			else
				echo "$1 is not a valid file."
				exit 1
			fi
			
			shift
		;;
	esac
done


function printObs() {
	if [ "$csv" == '1' ]
	then
		csvString="$target:$port"
		if [ "$pad" == '1' ];       then csvString=$(printf '%*s%s' 50 "$csvString"); fi;
		if [ "$ssl2" == '1' ];      then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$ssl3" == '1' ];      then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$tls1" == '1' ];      then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$tls11" == '1' ];     then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$skl" == '1' ];       then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$exprsa" == '1' ];    then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$expedh" == '1' ];    then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$rc4" == '1' ];       then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$dhe" == '1' ];       then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$descbc" == '1' ];    then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$pfs" == '1' ];       then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$sweet32" == '1' ];   then csvString="$csvString,x"; else csvString="$csvString,-"; fi;
		if [ "$poodletls" == '1' ]; then csvString="$csvString,x"; else csvString="$csvString,?"; fi;
		if [ "$insReneg" == '1' ];  then csvString="$csvString,x"; else csvString="$csvString,?"; fi;
		echo "$csvString"
	else
		echo "$target:$port"
		if [ "$ssl2" == '1' ] || [ "$ssl3" == '1' ] || [ "$tls1" == '1' ] || [ "$tls11" == '1' ]
			then
				echo '	Weak TLS/SSL version enabled: '
				if [ "$ssl2" == '1' ]; then echo '		SSLv2'; fi;
				if [ "$ssl3" == '1' ]; then echo '		SSLv3'; fi;
				if [ "$tls1" == '1' ]; then echo '		TLSv1.0'; fi;
				if [ "$tls11" == '1' ]; then echo '		TLSv1.1'; fi;
			fi
			if [ "$skl" == '1' ] || [ "$dhe" == '1' ] || [ "$descbc" == '1' ] || [ "$rc4" == '1' ] || [ "$exprsa" == '1' ] || [ "$expdh" == '1' ]
			then
				echo '	Weak TLS cipher-suites supported:'
				if [ "$skl" == '1' ];    then echo '		Short key length of cipher suites enabled (Less than 128 bits)'; fi;
				if [ "$exprsa" == '1' ]; then echo '		Export grade RSA cipher suites enabled'; fi;
				if [ "$expedh" == '1' ]; then echo '		Export grade EDH cipher suites enabled'; fi;
				if [ "$rc4" == '1' ];    then echo '		RC4 encryption algorithm based cipher suites enabled'; fi;
				if [ "$dhe" == '1' ];    then echo '		Short key length of DHE cipher suites (Less than 2048 bits)'; fi;
				if [ "$descbc" == '1' ]; then echo '		64-bit block size cipher suites supported'; fi;
				
			fi
			if [ "$pfs" == '1' ];        then echo '	Perfect Forward Secrecy not supported / Inadequate Perfect Forward Secrecy support (DH enabled cipher-suites are not preferred)'; fi;
			if [ "$sweet32" == '1' ];    then echo '	SWEET32'; fi;
			if [ "$poodletls" == '1' ];  then echo '	POODLE on TLS'; fi;
			if [ "$insReneg" == '1' ];   then echo '	Insecure renegotiation vulnerability (CVE-2009-3555)'; fi;
	fi
	target=''
	port=''
}

while IFS= read -r line
do
	finished=0
	while [ "$finished" == '0' ]
	do
		case "$line" in
			"Testing SSL server"*)
				[ -z $target ] || printObs
				target=$(echo "$line" | grep -Po '(?<=Testing SSL server )(.*)(?= on port)')
				port=$(echo "$line" | grep -Po '(?<=on port )(.*?)(?= )')
				tls1=0
				tls11=0
				descbc=0
				ssl2=0
				ssl3=0
				rc4=0
				dhe=0
				pfs=0
				skl=0
				exprsa=0
				expedh=0
				sweet32=0
				poodletls=0
				insReneg=0
				line="${line/Testing/---}"
			;;
			#"Insecure Renegotiation"*)
			#	insReneg=1
			#	line=''
			#;;
			"Failed"*|"Rejected"*)
				line=''
			;;
			"Preferred"*)
				exch=$(echo $line | grep -Po '(^.{59,})(DHE)')
				line="${line/Preferred/---}"
				if [ "$exch" == '' ]
				then
					pfs=1
				fi
			;;
			*"SSLv2"*)
				line="${line/SSLv2/---}"
				ssl2=1
			;;
			*"SSLv3"*)
				line="${line/SSLv3/---}"
				ssl3=1
			;;		
			*"TLSv1.0"*)
				line="${line/TLSv1.0/---}"
				tls1=1
			;;
			*"TLSv1.1"*)
				line="${line/'TLSv1.1'/---}"
				tls11=1
			;;
			*"RC4"*)
				line="${line/'RC4'/---}"
				rc4=1
			;;
			#*"DES"*|*"CBC"*|*"blowfish"*)
			*"DES"*|*"blowfish"*)
				line="${line/112 bits/---}"
				line="${line/DES/---}"
				line="${line/blowfish/---}"
				expgrep=$(echo $line | grep -E 'CBC')
				if [ "$expgrep" != '' ]
				then
					line="${line/CBC/---}"
					sweet32=1
				fi
				descbc=1
			;;
			*EXP*)
				expgrep=$(echo $line | grep -E 'EXP.*?RSA')
				if [ "$expgrep" != '' ]; then exprsa=1; fi;
				expgrep=$(echo $line | grep -E 'EXP.*?EDH')
				if [ "$expgrep" != '' ]; then expedh=1; fi;
				line="${line/EXP/---}"
				expgrep=''
			;;
			*"DHE "???" bits"|*"DHE "????" bits")		
				bits=$(echo $line | grep -Po '(?<=DHE )(.*)(?= bits$)')
				line="${line//DHE/---}"
				if [[ "$bits" =~ ^[0-9]+$ ]]
				then
					if [ "$bits" -lt '2048' ]
					then
						dhe=1
					fi
				fi
				bits=''
			;;
			*"  "??" bits  "*|*"  "???" bits  "*)
			#Dejar al final
				bits=$(echo "$line" | grep -Po '(?<=  )(.{1,3})(?= bits  )')
				line=''
				if [[ "$bits" =~ ^[0-9]+$ ]]
				then
					if [ "$bits" -lt '128' ]
					then
						skl=1
					fi
				fi
				bits=''
			;;
			*)
				finished=1
			;;
		esac
	done
done <"$inputFile"
[ -z $target ] || printObs