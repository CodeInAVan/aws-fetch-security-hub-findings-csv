mkdir -p results
while IFS=, read -r AccountID ARN Email Name Status Joined_method Joined_timestamp; do
  # something with "$user" "$pass"
    echo $AccountID $Name
    mkdir -p results/$AccountID
    rm -rf results/$AccountID/*
    cp *yaml results/$AccountID
    cat settings_config.yaml | sed -i -e "s/111111111111/$AccountID/g" results/$AccountID/settings_config.yaml
    cat settings_sechub.yaml | sed -i -e "s/111111111111/$AccountID/g" results/$AccountID/settings_sechub.yaml
    pushd results/$AccountID/
    python3 ../../fetch_sec_findings.py $Name
    popd
    rm -f results/$AccountID/*yaml
done < Organization_accounts_information.csv
