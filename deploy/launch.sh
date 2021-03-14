#!/bin/bash -x

if [[ $EUID -eq 0 ]]; then
   echo -e "This script must not be run as root" 
   exit 1
fi
if [[ ! -d src ]]; then
    echo -e "Run this from the project root directory"
    exit 1
fi

if [[ -f .env ]]; then
    source .env
fi
if [[ -z "${APP_NAME}" ]]; then
    APP_NAME=appserver
fi
if [[ -z "${TAG_ENV}" ]]; then
    TAG_ENV=Dev
fi
if [[ -z "${TAG_PURPOSE}" ]]; then
    TAG_PURPOSE=Testing
fi

readonly ami_name=${APP_NAME}-$(date +'%F')
readonly userdata_script=deploy/user-data/${APP_NAME}.sh
if [[ ! -f ${userdata_script} ]]; then
    echo "couldn't locate userdata script [${userdata_script}]"
    exit 1
fi
if [[ -z "${TARGET_GROUP_ARN}" ]]; then
    echo "TARGET_GROUP_ARN missing"
    exit 1
fi
if [[ -z "${SUBNET_ID}" ]]; then
    echo "SUBNET_ID missing"
    exit 1
fi
if [[ -z "${IAM_INSTANCE_PROFILE}" ]]; then
    echo "IAM_INSTANCE_PROFILE missing"
    exit 1
fi
if [[ -z "${NUM_INSTANCES}" ]]; then
    NUM_INSTANCES=$1
fi
if [[ -z "${NUM_INSTANCES}" ]] || [[ ${NUM_INSTANCES} =~ ^-?[0-9]+$ ]]; then
    NUM_INSTANCES=1
fi
if [[ -z "${COST_CENTER}" ]]; then
    COST_CENTER=randd
fi
if [[ -z "${PRIV_KEY_NAME}" ]]; then
    PRIV_KEY_NAME=trivialsec-baker
fi
if [[ -z "${SECURITY_GROUP_IDS}" ]]; then
    SECURITY_GROUP_IDS='sg-0652a48752a2da5a8 sg-01bbdeecc61359d59'
fi
if [[ -z "${DEFAULT_INSTANCE_TYPE}" ]]; then
    DEFAULT_INSTANCE_TYPE=t2.micro
fi

readonly image_id=$(aws ssm get-parameter --name "/${TAG_ENV}/AMI/${APP_NAME}-latest" --query "Parameter.Value" --output text)
if [[ ${image_id} != ami-* ]]; then
    echo "AMI not found, got: ${image_id}"
    exit 1
fi
declare -a old_instances_query=\($(aws elbv2 describe-target-health --target-group-arn ${TARGET_GROUP_ARN} --query 'TargetHealthDescriptions[].Target.Id' --output text)\)
old_targets=''
old_instances=''
for old_instance_id in "${old_instances_query[@]}"; do
    old_targets="${old_targets} Id=${old_instance_id},Port=80"
    old_instances="${old_instances} ${old_instance_id}"
done

readonly app_tags="[{Key=Name,Value=App},{Key=Environment,Value=${TAG_ENV}},{Key=Purpose,Value=${TAG_PURPOSE}},{Key=cost-center,Value=${COST_CENTER}}]"
declare -a results=\($(aws ec2 run-instances \
    --no-associate-public-ip-address \
    --image-id ${image_id} \
    --count ${NUM_INSTANCES} \
    --instance-type ${DEFAULT_INSTANCE_TYPE} \
    --key-name ${PRIV_KEY_NAME} \
    --subnet-id ${SUBNET_ID} \
    --security-group-ids ${SECURITY_GROUP_IDS} \
    --iam-instance-profile Name=${IAM_INSTANCE_PROFILE} \
    --credit-specification 'CpuCredits=standard' \
    --tag-specifications "ResourceType=instance,Tags=${app_tags}" "ResourceType=volume,Tags=${app_tags}" \
    --user-data file://${userdata_script} \
    --query 'Instances[].InstanceId' --output text)\)

new_targets=''
new_instances=''
for instance in "${results[@]}"; do
    new_targets="${new_targets} Id=${instance},Port=80"
    new_instances="${new_instances} ${instance}"
done
aws ec2 wait instance-running --instance-ids${new_instances}
aws ec2 wait instance-status-ok --instance-ids${new_instances}
aws elbv2 register-targets \
    --target-group-arn ${TARGET_GROUP_ARN} \
    --targets${new_targets}

if ! [[ -z "${old_targets}" ]]; then
    aws elbv2 deregister-targets --target-group-arn ${TARGET_GROUP_ARN} --targets${old_targets}
    aws ec2 terminate-instances --instance-ids${old_instances}
fi
echo Deployed ${NUM_INSTANCES} ${image_id}
exit 0
