#include <iostream>
#include <cstdio>
#include <netinet/in.h>
#include <cstdbool>
#include <pcap.h>
#include <string>
#include "mac.h"
#include <vector>

using namespace std;

struct RadioTapHdr {
    uint8_t ver;
    uint8_t pad;
    uint16_t len;
    uint16_t present;
};

// https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/
struct WlMacHeader {
    uint8_t type;
    uint8_t flag;
    uint16_t dur_id;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;
};

struct BeaconHeader1 {
    uint64_t timestamp;
    uint16_t bc_itv;
    uint16_t cp_info;
    uint8_t t_num;
    uint8_t t_len;
};

struct BeaconInfo {
    string bssid;
    int bcs;
    string essid;
};

void print_syntax() {
    cout << "syntax : airodump <interface>" << endl;
    cout << "sample : airodump mon0" << endl;
    cout << "compile : g++ main.cpp -o airodump -lpcap" << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "parameter error!" << endl << endl;
        print_syntax();
    }

    vector<struct BeaconInfo> bc_info;

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

    struct pcap_pkthdr* header;
	const u_char* packet;

    while(1) {
        int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
        /*
		for (int num1 = 0; num1 < header->caplen; num1++) {
			printf("%x", packet[num1]);
		}
		printf("\n");
        */

        struct RadioTapHdr* radio_tap_hdr = (struct RadioTapHdr*) packet;
        struct WlMacHeader* wl_mac_hdr = (struct WlMacHeader*) (packet + radio_tap_hdr->len);
        
        if (wl_mac_hdr->type != 0x80) {
            continue;
        }
        
        struct BeaconHeader1* bc_hdr1 = (struct BeaconHeader1*) (packet + radio_tap_hdr->len + sizeof(struct WlMacHeader));

        string essid;
        const u_char* essid_idx = (const u_char*)(packet + radio_tap_hdr->len + sizeof(struct WlMacHeader) + sizeof(struct BeaconHeader1) - 2);
        for (int num1 = 0; num1 < bc_hdr1->t_len; num1++) {
            essid.push_back(*essid_idx);
            essid_idx += 1;
        }

        int ck = 0;
        for (int num1 = 0; num1 < bc_info.size(); num1++) {
            if (bc_info[num1].bssid == string(wl_mac_hdr->bssid)) {
                bc_info[num1].bcs += 1;
                ck = 1; 
                break;
            }
        }
        
        if (ck == 0) {
            struct BeaconInfo bc_info1;
            bc_info1.bcs = 1;
            bc_info1.bssid = string(wl_mac_hdr->bssid);
            bc_info1.essid = essid;
            bc_info.push_back(bc_info1);
        }


        system("clear");
        cout << "BSSID\t\t\tBeacons\t\tBSSID\n\n" << endl;
        for (int num1 = 0; num1 < bc_info.size(); num1++) {
            cout << bc_info[num1].bssid << "\t";
            cout << bc_info[num1].bcs << "\t\t";
            cout << bc_info[num1].essid << endl;
        }
    }
    pcap_close(pcap);
}
