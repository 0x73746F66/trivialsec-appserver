#!/bin/bash -x

if [[ $EUID -eq 0 ]]; then
   echo -e "This script must not be run as root" 
   exit 1
fi
if [[ ! -d scripts ]]; then
    echo -e "Run this from the project root directory"
    exit 0
fi

NUM_INSTANCES=$1
if [[ -z "${NUM_INSTANCES}" ]] || [[ ${NUM_INSTANCES} =~ ^-?[0-9]+$ ]]; then
    NUM_INSTANCES=1
fi
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-southeast-2:814504268053:targetgroup/trivialsec-prod/fcf5cd3c70ceb857

declare -a old_instances=\($(aws elbv2 describe-target-health --target-group-arn ${TARGET_GROUP_ARN} --query 'TargetHealthDescriptions[].Target.Id' --output text)\)
targets=''
instances=''
for instanceId in "${old_instances[@]}"; do
    targets="${targets} Id=${instanceId},Port=80"
    instances="${instances} ${instanceId}"
done

imageId=$(scripts/deploy/bake-ami.sh app sg-0652a48752a2da5a8 160|tail -n1)
if [[ ${imageId} == ami-* ]]; then
    ./scripts/deploy/stage2-app.sh ${imageId} ${NUM_INSTANCES}
    if [[ $? -eq 0 ]]; then
        aws elbv2 deregister-targets --target-group-arn ${TARGET_GROUP_ARN} --targets${targets}
        aws ec2 terminate-instances --instance-ids${instances}
    fi
fi
echo "$imageId"
