#!/bin/bash

###################################################################
#
# This script uses aws cli and jq (https://stedolan.github.io/jq/).
#
###################################################################

max_num_msgs=10
wait_time_secs=2
visibility_timeout=30
invalid_token_error="ExpiredToken"
queue_not_found="AWS.SimpleQueueService.NonExistentQueue"

AWS_REGION=us-east-1
ACTION=INFO
MSG_ATTRS_TO_RETRIEVE=""
JQ_MSG_ATTR_FILTER=""
MSG_ATTRIBUTES_KEY_VALS=""
NUM_OF_MSGS_TO_SCAN=1000
DEBUG_LOG=false

red_txt=$(tput setaf 1)
green_txt=$(tput setaf 2)
blue_txt=$(tput setaf 4)
white_txt=$(tput setaf 7)
bold=$(tput bold)
normal=$(tput sgr0)

function process_arguments() {
     while [ $# -gt 0 ]; do
          curr_arg=$1
          case $curr_arg in
          --queue-name | -q)
               QUEUE_NAME="$2"
               shift 2
               ;;
          --message-attributes-filter)
               MSG_ATTRIBUTES_KEY_VALS="$2"
               shift 2
               ;;
          --num-of-msgs-to-scan)
               NUM_OF_MSGS_TO_SCAN="$2"
               shift 2
               ;;
          --action | -a)
               ACTION="$2"
               shift 2
               ;;
          --help | -h)
               print_help "--help"
               shift
               ;;
          --debug-log)
               DEBUG_LOG=true
               shift
               ;;
          *)
               OTHER_ARGUMENTS+=("$1")
               shift
               ;;
          esac
     done
}

function process_msg_attribute_key_val() {

     log_debug_msg "Process msg attributes $MSG_ATTRIBUTES_KEY_VALS"
     # Read the msg attributes passed from command line. Split them using delimeter ',' using -d flag. Then split each key value pair.
     while read -d, -r key_val_pair; do
          IFS='=' read -r key value <<<"$key_val_pair"
          temp_filter='select(.MessageAttributes  | to_entries[]|(.key == "__KEY__") and (.value.StringValue == "__VALUE__"))'
          temp_filter="${temp_filter/__KEY__/$key}"
          temp_filter="${temp_filter/__VALUE__/$value}"
          MSG_ATTRS_TO_RETRIEVE="${MSG_ATTRS_TO_RETRIEVE} ${key}"
          JQ_MSG_ATTR_FILTER="${JQ_MSG_ATTR_FILTER} ${temp_filter} |"
     done <<<"$MSG_ATTRIBUTES_KEY_VALS,"
}

function get_sqs_queue_url() {
     QUEUE_URL=$(aws sqs get-queue-url --queue-name $QUEUE_NAME --region $AWS_REGION 2>/dev/null | jq -r '.QueueUrl')
     if [ -z "$QUEUE_URL" ]; then
          log_error_msg "Unable to retrieve Queue URL. Please check queue name and/or STS token."
     fi
     log_debug_msg "Queue URL is $QUEUE_URL"
}

function check_prerequisites() {

     # Check if jq is installed.
     if [ -z "$(command -v jq)" ]; then
          log_error_msg "jq is missing. Please refer to https://stedolan.github.io/jq/"
          exit 1
     fi

     # Check if aws cli is installed.
     if [ -z "$(command -v aws)" ]; then
          log_error_msg "aws is missing. Please refer to https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
          exit 1
     fi

}

function validate_input_arguments() {

     # Validate Action argument value.

     is_valid_action

     #Validate Queue.
     validate_queue_name

     validate_msg_attributes
     validate_num_of_msg_to_scan

}

# Check for queue existance.
# Queue name should not be blank and queue must exist.
function validate_queue_name() {

     # Check for blank queue name.
     log_debug_msg "Queue name is $QUEUE_NAME"
     if [ -z "$QUEUE_NAME" ]; then
          log_error_msg "Queue name must not be blank."
          print_help
     fi
}

# Is this still useful?
function is_valid_queue() {

     # Check if queue exists in AWS.
     get_sqs_queue_url
     if [ -z "$QUEUE_URL" ]; then
          log_error_msg "Unable to retrieve Queue URL. Please check queue name and/or STS token."
          print_help
     fi

}

function validate_num_of_msg_to_scan() {

     if [[ !("$NUM_OF_MSGS_TO_SCAN" =~ ^[0-9]+$) || -z "$NUM_OF_MSGS_TO_SCAN" || "$NUM_OF_MSGS_TO_SCAN" -le 0 || "$NUM_OF_MSGS_TO_SCAN" -gt 1000 ]]; then
          log_error_msg "--num-of-msgs-to-scan value must be between 1 and 1000."
          print_help
     fi

     if [ "$NUM_OF_MSGS_TO_SCAN" -lt 10 ]; then
          max_num_msgs=$NUM_OF_MSGS_TO_SCAN
     fi

}

function is_valid_action() {
     log_debug_msg "Validating message action. Message action is $ACTION"
     if ! [[ "$ACTION" == "INFO" || "$ACTION" == "DELETE" ]]; then
          log_error_msg "--action parameter value must be either INFO or DELETE. Default value is INFO. "
          print_help
     fi
}

function validate_msg_attributes() {
     log_debug_msg "validate_msg_attributes"
     process_msg_attribute_key_val
     log_debug_msg "MSG_ATTRS_TO_RETRIEVE is ${MSG_ATTRS_TO_RETRIEVE}"
     if [ -z "${MSG_ATTRS_TO_RETRIEVE// /}" ]; then
          log_error_msg "You must pass at least one msg attribute and value."
          print_help
     fi
}

function generate_jq_msg_filter_cmd() {
     JQ_MSG_FILTER_CMD='jq -c -r -M '"'"'[.Messages[] | select(.MessageAttributes | length > 0) | __JQ_MSG_ATTR_FILTER__ {MessageId, MessageAttributes, ReceiptHandle} ]'"'"'  <<< $messages'
     if [ -z "$JQ_MSG_ATTR_FILTER" ]; then
          process_msg_attribute_key_val
     fi
     JQ_MSG_FILTER_CMD="${JQ_MSG_FILTER_CMD/__JQ_MSG_ATTR_FILTER__/$JQ_MSG_ATTR_FILTER}"
}

function process_sqs_queue_msgs() {

     generate_jq_msg_filter_cmd

     counter=0
     while [ $counter -lt $NUM_OF_MSGS_TO_SCAN ]; do

          messages=$(
               aws sqs receive-message --queue-url $QUEUE_URL --max-number-of-messages $max_num_msgs \
               --wait-time-seconds $wait_time_secs --visibility-timeout $visibility_timeout --message-attribute-names $MSG_ATTRS_TO_RETRIEVE
          )

          if $DEBUG_LOG; then
               log_json $messages
          fi

          new_msg_count=$(jq -c -r -M '.Messages | length' <<<$messages)

          if [ -z "$new_msg_count" ]; then
               log_msg "No new messages returned. Stopping the poll."
               break
          fi

          filtered_messages=$(eval "$JQ_MSG_FILTER_CMD")

          log_msg "Filtered Msgs (i.e. Msgs matching the given msg attributes): "
          jq '[.[] | {MessageId,MessageAttributes} ]' <<<$filtered_messages

          if [ "$ACTION" == "DELETE" ]; then

               filtered_msg_count=$(jq -c -r -M '. | length' <<<$filtered_messages)

               if [ $filtered_msg_count -gt 0 ]; then
                    log_msg "Deleting Messages From Queue"
                    jq -c -M '.[] | "Id=" + .MessageId + ",ReceiptHandle=" + .ReceiptHandle' <<<$filtered_messages | \
                    xargs aws sqs delete-message-batch --queue-url $QUEUE_URL --entries | \
                    jq '.'
               fi
          fi

          counter=$(($counter + $new_msg_count))

          if [ "$counter" -ge $NUM_OF_MSGS_TO_SCAN ]; then
               log_msg "Reached the number of msg limit ($NUM_OF_MSGS_TO_SCAN). Current count: $counter. Stopping the poll."
          fi
     done
}

function print_help() {
     log_msg "
     
Description
***********

Use this script to View and/or Delete the messages thats matching the given message attributes and its values.


Synopsis 
********

       $0 
     --queue-name | -q <value>
     --message-attributes-filter <value>
     [--num-of-msgs-to-scan <value>]
     [--action < INFO | DELETE >]
     [--help | -h]
     [--debug-log]


Options
*******

\"--queue-name\" | \"-q\" (string)

     The name of the queue from where the messages must be fetched. Maximum 80
     characters. Valid values: alphanumeric characters, hyphens (\"-\" ),
     and underscores (\"_\" ).

     Queue name is case-sensitive.

\"--message-attributes-filter\" (string)

     The message attributes to query for messages. Pass message attributes as key=value pair.
     Pass multiple attributes as comma separated string. Pass the string in double quotes.

\"--num-of-msgs-to-scan\" (number)

     Number of messages to retrive from the queue before stopping the poll. 
     The value must be between 1-1000. Default value is 1000.

\"--action\" (INFO|DELETE)

     The message action to perform. 
     INFO - Prints out messages that matches the given \"--message-attributes-filter\".
     DELETE - Prints out messages that matches the given \"--message-attributes-filter\" 
          and deletes them from the queue. Also prints out delete message status.

\"--help\" | \"-h\" (string)

     Prints how to use this script and details about all the options.

\"--debug-log\" (string)

     Log additional messages to help debug the script.


Examples
********

     Example 1:
     ----------
     $0 --queue-name MyQueue --message-attributes-filter \"company=css,location=Bethesda\" \\
     --num-of-msgs-to-scan 256 --action DELETE --debug-log


     Example 2:
     ----------
     $0 --queue-name MyQueue --message-attributes-filter \"key=value\"


     Example 3:
     ----------
     $0 --help

"

     if [ -z "$1" ]; then
          exit 1
     fi
     exit 0
}

# Takes a string argument and splits it by space.
function split_string_by_space() {
     IFS=' ' read -ra split_str_arr <<<"$1"
     NUM_OF_ELEM=${#split_str_arr[@]}
}

function log_msg() {
     # echo "[$(date "+%F %T")] [${bold}${2:-INFO }${normal}] : $1"
     echo "${bold}[$(date "+%F %T")] [${2:-${green_txt}INFO ${white_txt}}] : $1"
}

function log_error_msg() {
     #  echo "${red_txt}${bold}[$(date "+%F %T")] [ERROR]${normal} : $1"
     log_msg "$1" "${red_txt}ERROR${white_txt}"
}

function log_debug_msg() {
     if $DEBUG_LOG; then
          log_msg "$1" "${blue_txt}DEBUG${white_txt}"
     fi
}

function log_json() {
     jq '.' <<<$1
}

log_msg "Started executing the script."

# Check all the prerequisites are available.
check_prerequisites

# Read the command line input arguments
process_arguments "$@"

# Validate input arguments for any missing/invalid values.
validate_input_arguments

# Get SQS Queue URL.
get_sqs_queue_url

# Read SQS messages and perform the specified actions that match the message attributes.
process_sqs_queue_msgs

log_msg "Completed executing the script."

exit 0
