#!/bin/bash

# This script will be ran by elastAlert to send Wazuh alerts to theHive API
# The goal of this script is to be very extndable and changeable.
# Alerts will be sent in an easy to read format, along with the elasticSearch document ID, Wazuh event ID, agent, rule and event inforamtion. Source IP addresses will be added as oberavables, and the rule groups will be added as tags.

#System Variables
hive_api_url="HIVE_URL_HERE"
hive_api_key="API_KEY_HERE"
logfile="/var/log/elastalert/Hive-Alerts.log"
whitelist_file="/home/elastalert/elastalert_files/command-scripts/hive-alerts-whitelist.json"
debug="False"

# Alert Variables
## Agent
data_agent_id="None"
data_agent_name="None"
data_agent_ip="None"
## Rule
data_rule_description="None"
data_rule_id="None"
data_rule_level="None"
## Data
data_data_srcip="None"
data_data_web_srcip="None"
data_eventchannel_srcip="None"
data_rule_groups="None"
## FIM
fim_sha256="None"
whitelist_match=0

##Alert
alert_datetime="None"
alert_elk_id="None"
alert_wazuh_id="None"


#System Variables
var_source_ip="None"
var_uuid="$(openssl rand -hex 8)"
observables=""

data_full_log="None"

show_usage() {

    echo "You done fucked up bro..."

}

#Get right IP field

getSourceIP(){

if [ ! "$data_data_srcip" = "None" ] || [ ! "$data_data_srcip" = "" ]; then
    var_source_ip="$data_data_srcip"
    if [ "$debug" = "True" ]; then
        echo "$(date) [Info] [Send alerts to TheHive] Source IP set to data.srcip" >> $logfile
    fi
    elif [ ! "$data_data_web_srcip" = "None" ] || [ ! "$data_data_web_srcip" = "" ]; then
    if [ "$debug" = "True" ]; then
        echo "$(date) [Info] [Send alerts to TheHive] Source IP ser to data.web.srcip" >> $logfile
    fi
        var_source_ip=$data_data_web_srcip
            elif [ ! "$data_eventchannel_srcip" = "None" ] || [ ! "$data_eventchannel_srcip" = "" ]; then
            if [ "$debug" = "True" ]; then
                echo "$(date) [Info] [Send alerts to TheHive] Source IP set to data.eventchannel.SourceIP" >> $logfile
            fi
                var_source_ip=$data_eventchannel_srcip
                else
                    var_source_ip="None"
                    if [ "$debug" = "True" ]; then
                        echo "$(date) [Info] [Send alerts to TheHive] No valid source IP field found. Not setting one" >> $logfile
                    fi

fi
}

#Build Observables

buildObservables() {

#The agent name obvervable will allways be here, so we can use this as the end item in the JSON string, then prepend others to the obvervables variable
observables="{ \"dataType\": \"ip\", \"data\": \"$data_agent_ip\", \"tags\": [\"agent_ip\", \"ID: $data_agent_id\", \"Name: $data_agent_name\"] }"

## Prepend attacking IP Observables
# Get Attacking IP tags

if [[ $var_source_ip = "None" ]] || [[ $var_source_ip = "" ]]; then

    if [ "$debug" = "True" ]; then
        echo "$(date) [Info] [Send alerts to TheHive] Source IP set to None, NOT setting overvable" >> $logfile
    fi

else
    if [ "$debug" = "True" ]; then
        echo "$(date) [Info] [Send alerts to TheHive] Source IP variable was not none, setting oberavable..." >> $logfile
    fi

    str=$(echo "$data_rule_groups" | tr -d []\'\")

    IFS=", "
    read -ra ADDR <<< "$str"
    for i in "${ADDR[@]}"; do
            rule_group_tags="\"$i\", $rule_group_tags"
    done
    IFS=' '

if [ ! $var_source_ip = "None" ] || [ ! $var_source_ip = "" ]; then
    # Make Obervable with tags
    observables="{ \"dataType\": \"ip\", \"data\": \"$var_source_ip\", \"tags\": [$rule_group_tags\"attacking_ip\"] },$observables"
fi

fi


## GET FIM Hash tags

if (echo $data_rule_groups | grep "syscheck"); then

    if [ $fim_sha256 = "None" ] || [ $fim_sha256 = "" ]; then

        if [ "$debug" = "True" ]; then
            echo "$(date) [Info] [Send alerts to TheHive] SHA256 variable was set to None, NOT setting an onservable" >> $logfile
        fi

    else

        if [ "$debug" = "True" ]; then
            echo "$(date) [Info] [Send alerts to TheHive] FIM Sha256 IP variable is not none, setting overvable" >> $logfile
        fi

        #Snaitise Sha256
        str="$(echo "$fim_sha256" | tr -d []\'\")"

        str=$(echo "$data_rule_groups" | tr -d []\'\")

        IFS=", "
        read -ra ADDR <<< "$str"
        for i in "${ADDR[@]}"; do
                rule_group_tags="\"$i\", $rule_group_tags"
        done
        IFS=' '


            # Make Obervable with tags
            observables="{ \"dataType\": \"hash\", \"data\": \"$fim_sha256\", \"tags\": [$rule_group_tags\"sha256_after\"] },$observables"

    fi

fi

}

sendAlert() {
# Send Alert

# Checking whitelist
while read -r line || [[ -n $line ]];
do
   if (echo "$line" | jq -r .agent_id | grep "$data_agent_id") || (echo "$line" | jq -r .agent_id | grep "any"); then
        if [ "$debug" = "True" ]; then
             echo "$(date) [Info] [Send alerts to TheHive] Agent ID or * was found in whitelist file. Incrementing threshold value..." >> $logfile
        fi
         whitelist_match=$((whitelist_match+1))
    fi

    if (echo "$line" | jq -r .rule_id | grep "$data_rule_id") || (echo "$line" | jq -r .rule_id | grep "any"); then
        if [ "$debug" = "True" ]; then
             echo "$(date) [Info] [Send alerts to TheHive] Rule ID or all was found in whitelist file. Incrementing threshold value..." >> $logfile
        fi
         whitelist_match=$((whitelist_match+1))
    fi

    if (echo "$line" | jq -r .source_ip | grep "$var_source_ip") || (echo "$line" | jq -r .source_ip | grep "any"); then
        if [ "$debug" = "True" ]; then
             echo "$(date) [Info] [Send alerts to TheHive] Source IP or any was found in whitelist file. Incrementing threshold value..." >> $logfile
        fi
        whitelist_match=$((whitelist_match+1))

    fi

        if (echo "$line" | jq -r .full_log_regex | grep "None"); then 

            if [ "$debug" = "True" ]; then
                echo "$(date) [Info] [Send alerts to TheHive] No whitelist regex found" >> $logfile
            fi

        else

            if [ "$debug" = "True" ]; then
                echo "$(date) [Info] [Send alerts to TheHive] Found regex whitelist on line: $line " >> $logfile
            fi

            whitelist_regex=$(echo "$line" | jq -r .full_log_regex)


            if (echo "$whitelist_regex" | grep -e "^any$"); then

                if [ "$debug" = "True" ]; then
                    echo "$(date) [Info] [Send alerts to TheHive] Regex was set to any. Incrementing threshold value..." >> $logfile
                fi

             whitelist_match=$((whitelist_match+1))

            elif (grep -e "$whitelist_regex" $data_full_log); then

                if [ "$debug" = "True" ]; then
                    echo "$(date) [Info] [Send alerts to TheHive] Regex $whitelist_regex matched $data_full_log . Incrementing threshold value..." >> $logfile
                fi

             whitelist_match=$((whitelist_match+1))

             else

             echo "$(date) [Info] [Send alerts to TheHive] Regex was set, but the alert did not match the full_log field." >> $logfile

            fi

        fi


    if [ "$whitelist_match" = 4 ]; then

        echo "$(date) [Info] [Send alerts to TheHive] Alert DID match the whitelist threshold: $whitelist_match. Wont send request..." >> $logfile

    else
        if [ "$debug" = "True" ]; then
             echo "$(date) [Info] [Send alerts to TheHive] Alert did not match the whitelist threshold: $whitelist_match" >> $logfile
        fi
    fi

done <<<$(cat "$whitelist_file")


REQUEST_DATA="{\"tags\": [\"Rule ID: $data_rule_id\", \"Rule Level: $data_rule_level\", \"Agent ID: $data_agent_id\"],\"title\":\"$data_agent_id -> $data_rule_description\",\"description\":\"## Wazuh Alert \n\n\n**Agent Details**\n\n\nID: \`\`\`$data_agent_id\`\`\`\n\nName: \`\`\`$data_agent_name\`\`\`\n\nIP: \`\`\`$data_agent_ip\`\`\`\n\n\n**Rule Details**\n\n\nRule Description: \`\`\`$data_rule_description\`\`\`\n\n\n**Event Details**\n\nDate/time: \`\`\`$alert_datetime\`\`\`\n\nRule ID: \`\`\`$data_rule_id\`\`\`\n\nRule Level: \`\`\`$data_rule_level\`\`\`\n\n\nSource IP: \`\`\`$var_source_ip\`\`\`\n\n\nFull Log: \`\`\`$data_full_log)\`\`\`\n\nelasticSearch Document ID: \`\`\`$alert_elk_id\`\`\`\n\nWazuh Event ID: \`\`\`$alert_wazuh_id\`\`\`\",\"type\":\"Wazuh_Alert\",\"source\":\"Wazuh\",\"sourceRef\":\"$var_uuid\",\"severity\":1,\"tlp\":1,\"artifacts\":[$observables]}"



# Send the alert

if [ "$debug" = "True" ]; then
    echo "$(date) [Info] [Send alerts to TheHive] Whitelist value is $whitelist_match" >> $logfile
fi

if [ ! "$whitelist_match" = 4 ]; then

if [ "$debug" = "True" ]; then
    echo "$(date) [Info] [Send alerts to TheHive] Attempting to send web request..." >> $logfile
    echo -n "$REQUEST_DATA"
fi

    if RESPONSE=$(curl -s -XPOST -H "Authorization: Bearer $hive_api_key" -H 'Content-Type: application/json' $hive_api_url -d "$(echo -n $REQUEST_DATA)"); then

        if [ "$debug" = "True" ]; then
            echo "$(date) [Info] [Send alerts to TheHive] Received response..." >> $logfile
            echo "$RESPONSE" >> $logfile
        fi

    else

        echo "$(date) [Error] [Send alerts to TheHive] Unable to send web Request" >> $logfile
        echo "$RESPONSE" >> $logfile
    fi

    else

    echo "$(date) [Info] [Send alerts to TheHive] Not sending alert for $alert_elk_id as whitelisted" >> $logfile
    exit 0

fi

}

# Get command line data
while [ "$1" != "" ]; do
    case $1 in

        --agent-id )            shift
                                data_agent_id="$1"
                                ;;
        --agent-name )          shift
                                data_agent_name="$1"
                                ;;
        --agent-ip )            shift
                                data_agent_ip="$1"
                                ;;
        --rule-description )    shift
                                data_rule_description="$1"
                                ;;
        --rule-id )             shift
                                data_rule_id="$1"
                                ;;
        --rule-level )          shift
                                data_rule_level="$1"
                                ;;
        --rule-groups )         shift
                                data_rule_groups="$1"
                                ;;
        --data-data-srcip )     shift
                                data_data_srcip="$1"
                                ;;
        --data-data-web-srcip ) shift
                                data_data_web_srcip="$1"
                                ;;
        --data-data-eventchannel-srcip ) shift
                                data_eventchannel_srcip="$1"
                                ;;
        --data-full-log )       shift
                                data_full_log="$1"
                                ;;
        --fim-sha256 )          shift
                                fim_sha256="$1"
                                ;;
        --alert-elk-id )        shift
                                alert_elk_id="$1"
                                ;;
        --alert-wazuh-id )      shift
                                alert_wazuh_id="$1"
                                ;;
        --alert-datetime )      shift
                                alert_datetime="$1"
                                ;;
        --debug )               shift
                                debug="True"
                                ;;
        --help )                show_usage
                                exit
                                ;;
        * )                     show_usage
                                exit 1
    esac
    shift
done

# Creating initial log entry
echo "$(date) [Info] [Send alerts to TheHive] - Script ran for elasticSearch document id: $alert_elk_id" >> $logfile

if [ "$debug" = "True" ]; then
    echo "[Info] Received CLI Arguments: --debug $debug --alert-datetime $alert_datetime --alert-wazuh-id $alert_wazuh_id --alert-elk-id $alert_elk_id --data-full-log $data_full_log --data-data-eventchannel-srcip $data_eventchannel_srcip --data-data-web-srcip $data_data_web_srcip --data-data-srcip $data_data_srcip --rule-groups $data_rule_groups --rule-level $data_rule_level --rule-id $data_rule_id --rule-description $data_rule_description --agent-ip $data_agent_ip --agent-name $data_agent_name --agent-id $data_agent_id" >> $logfile
fi

getSourceIP
buildObservables
sendAlert
exit 0
