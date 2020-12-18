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
readonly ami_name=app-$(date +'%F')
readonly baker_script=deploy/user-data/baker.sh
readonly userdata_script=deploy/user-data/appserver.sh
if [[ ! -f ${baker_script} ]]; then
    echo "couldn't locate baker script [${baker_script}]"
    exit 1
fi
if [[ ! -f ${userdata_script} ]]; then
    echo "couldn't locate userdata script [${userdata_script}]"
    exit 1
fi
if [[ -z "${BASE_AMI}" ]]; then
    echo "BASE_AMI missing"
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
    PRIV_KEY_NAME=trivialsec-dev
fi
if [[ -z "${SECURITY_GROUP_IDS}" ]]; then
    SECURITY_GROUP_IDS='sg-04a8dac724adcad3c sg-01bbdeecc61359d59'
fi
if [[ -z "${DEFAULT_INSTANCE_TYPE}" ]]; then
    DEFAULT_INSTANCE_TYPE=t2.micro
fi

mkdir -p /root/.ssh
aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-keys/${PRIV_KEY_NAME}.pem /root/.ssh/${PRIV_KEY_NAME}.pem
chmod 400 /root/.ssh/${PRIV_KEY_NAME}.pem
eval $(ssh-agent -s)
ssh-add /root/.ssh/${PRIV_KEY_NAME}.pem
ssh-keyscan -H proxy.trivialsec.com >> /root/.ssh/known_hosts

declare -a old_instances_query=\($(aws elbv2 describe-target-health --target-group-arn ${TARGET_GROUP_ARN} --query 'TargetHealthDescriptions[].Target.Id' --output text)\)
old_targets=''
old_instances=''
for old_instance_id in "${old_instances_query[@]}"; do
    old_targets="${old_targets} Id=${old_instance_id},Port=80"
    old_instances="${old_instances} ${old_instance_id}"
done

instanceId=$(aws ec2 run-instances \
    --no-associate-public-ip-address \
    --image-id ${BASE_AMI} \
    --count 1 \
    --instance-type ${DEFAULT_INSTANCE_TYPE} \
    --key-name ${PRIV_KEY_NAME} \
    --subnet-id ${SUBNET_ID} \
    --security-group-ids ${SECURITY_GROUP_IDS} \
    --iam-instance-profile Name=${IAM_INSTANCE_PROFILE} \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=Baker-app},{Key=appserver,Value=baking},{Key=cost-center,Value=${COST_CENTER}}]" "ResourceType=volume,Tags=[{Key=cost-center,Value=${COST_CENTER}}]" \
    --user-data file://${baker_script} \
    --query 'Instances[].InstanceId' \
    --output text)

if [[ ${instanceId} != i-* ]]; then
    echo AMI baking failed to start
    exit 1
fi
aws ec2 wait instance-running --instance-ids ${instanceId}
echo "PrivateIpAddress $(aws ec2 describe-instances --instance-ids ${instanceId} --query 'Reservations[].Instances[].PrivateIpAddress' --output text)"
aws ec2 wait instance-status-ok --instance-ids ${instanceId}
readonly privateIp=$(aws ec2 describe-instances --instance-ids ${instanceId} --query 'Reservations[].Instances[].PrivateIpAddress' --output text)
readonly existingImageId=$(aws ec2 describe-images --owners self --filters "Name=name,Values=${ami_name}" --query 'Images[].ImageId' --output text)
if [[ "${existingImageId}" == ami-* ]]; then
    aws ec2 deregister-image --image-id ${existingImageId}
    sleep 3
fi
while ! [ $(ssh -o 'StrictHostKeyChecking no' -o 'CheckHostIP no' -4 -J ec2-user@proxy.trivialsec.com ec2-user@${privateIp} 'echo `[ -f .deployed ]` $?') -eq 0 ]
do
    sleep 2
done
scp -o 'StrictHostKeyChecking no' -o 'CheckHostIP no' -4 -J ec2-user@proxy.trivialsec.com ec2-user@${privateIp}:/var/log/user-data.log .
cat user-data.log
readonly image_id=$(aws ec2 create-image --instance-id ${instanceId} --name ${ami_name} --description "Baked $(date +'%F %T')" --query 'ImageId' --output text)
sleep 60
aws ec2 wait image-available --image-ids ${image_id}
aws ec2 terminate-instances --instance-ids ${instanceId}
if [[ ${image_id} != ami-* ]]; then
    echo AMI baking failed
    exit 1
fi
declare -a results=\($(aws ec2 run-instances \
    --no-associate-public-ip-address \
    --image-id ${image_id} \
    --count ${NUM_INSTANCES} \
    --instance-type ${DEFAULT_INSTANCE_TYPE} \
    --key-name ${PRIV_KEY_NAME} \
    --subnet-id ${SUBNET_ID} \
    --security-group-ids ${SECURITY_GROUP_IDS} \
    --iam-instance-profile Name=${IAM_INSTANCE_PROFILE} \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=App},{Key=appserver,Value=production},{Key=cost-center,Value=${COST_CENTER}}]" "ResourceType=volume,Tags=[{Key=cost-center,Value=${COST_CENTER}}]" \
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
echo ${image_id}
exit 0
