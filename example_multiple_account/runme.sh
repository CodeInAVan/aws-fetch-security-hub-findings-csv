mkdir -p results
cp Organization_accounts_information.csv Organization_accounts_information_old.csv
tr -cd '\11\12\15\40-\176' < Organization_accounts_information_old.csv > Organization_accounts_information.csv
rm Organization_accounts_information_old.csv -f
#iconv -f utf-8 -t utf-8 -c Organization_accounts_information_old.csv -o Organization_accounts_information.csv
while IFS=, read -r AccountID ARN Email Name Status Joined_method Joined_timestamp; do
  # something with "$user" "$pass"
    echo $AccountID $Name
    mkdir -p results/$AccountID
    #echo $AccountID > test.json
    rm -rf results/$AccountID/*
    cp *yaml results/$AccountID
    export strReplace="s/111111111111/$AccountID/g"
    #echo $strReplace
    cat settings_config.yaml | sed -i -e $strReplace results/$AccountID/settings_config.yaml
    cat settings_sechub.yaml | sed -i -e $strReplace results/$AccountID/settings_sechub.yaml
    pushd results/$AccountID/ > /dev/null
    python3 ../../fetch_sec_findings.py $Name
    popd > /dev/null
    sleep 3
    rm -f results/$AccountID/*yaml
done < Organization_accounts_information.csv
