# analysis.awk -- analysis iwlist scanning result to json
# sta[0]["bssid"]=
# sta[0]["ssid"]=
# sta[0]["channel"]=
# sta[0]["rssi"]=
# sta[0]["bandwidth"]=
# sta[0]["mode"]=

/Cell [0-9]* - Address:/{
    sta[0]=$5;
    while (getline > 0) {
        if(match($0,"ESSID:")) {
            split($0, aa, ":|\"");
            sta[1]=aa[3];
        } else if(match($1, "Frequency:.*")) {
            split($4, aa, ")");
            sta[2]=aa[1];
        } else if(match($2, "Signal")) {
            split($3, aa, "=");
            sta[3]=aa[2];
        } else if(match($1, "Extra:phy_mode=.*")) {
            split($1, aa, "=");
            mode=aa[2];
            split(mode, aa, "_");
            if(match(aa[4], "20")) {
                sta[4]=20;
            } else if(match(aa[4], "40")) {
                sta[4]=40;
            } else if(match(aa[4], "80")) {
                sta[4]=80;
            } else {
                sta[4]=20;
            }
            sta[5]=0;
            if(match(aa[3], "AC")) {
                sta[5]=0x10;
            } else if(match(aa[3], "NG")) {
                sta[5]=0xc;
            } else if(match(aa[3], "NA")) {
                sta[5]=0x9;
            } else if(match(aa[3], "11G")) {
                sta[5]=0x4;
            } else if(match(aa[4], "11A")) {
                sta[5]=0x1;
            }
            break;
        }
    }
    printf("%s|%s|%s|%s|%s|%s\n", sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
}
