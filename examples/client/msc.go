// Command client creates Begin/Invoke packet with given parameters, and send it to the specified address.
// By default, it sends MAP cancelLocation. The parameters in the lower layers(SCTP/M3UA/SCCP) cannot be
// specified from command-line arguments. Update this source code itself to update them.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/ishidawataru/sctp"
	"github.com/wmnsk/go-m3ua"
	m3params "github.com/wmnsk/go-m3ua/messages/params"
	"github.com/wmnsk/go-sccp"
	"github.com/wmnsk/go-sccp/params"
	"github.com/wmnsk/go-sccp/utils"
	"github.com/wmnsk/go-tcap"
)

func parsePC(s *string) uint32 {
	ret := uint32(0)
	pcAndLen := strings.Split(*s, "/")
	pc := pcAndLen[0]
	len, _ := strconv.Atoi(pcAndLen[1])
	digits := strings.Split(pc, ".")
	a, _ := strconv.Atoi(digits[0])
	b, _ := strconv.Atoi(digits[1])
	c, _ := strconv.Atoi(digits[2])

	if len == 14 {
		ret = uint32(c | b<<3 | a<<11)
	} else if len == 24 {
		ret = uint32(c | b<<8 | a<<16)
	} else {
		log.Fatal("invalid point code length")
	}
	return ret
}

func main() {
	var (
		laddr   = flag.String("laddr", "192.168.16.11:29050", "local IP and Port to bind.")
		raddr   = flag.String("raddr", "192.168.11.39:5001", "Remote IP and Port to connect to.")
		opc     = flag.String("opc", "0.5.1/14", "local signaling point code")
		dpc     = flag.String("dpc", "0.1.2/14", "remote signaling point code")
		cdparty = flag.String("cdparty", "861390001", "called party digit")
		cgparty = flag.String("cgparty", "861380000", "calling party digit")
		otid    = flag.Int("otid", 0x11111111, "Originating Transaction ID in uint32.")
		opcode  = flag.Int("opcode", 56, "Operation Code in int.")
		payload = flag.String("payload", "800864009000256688f0020104830100", "Hex representation of the payload")
	)
	flag.Parse()

	p, err := hex.DecodeString(*payload)
	if err != nil {
		log.Fatal(err)
	}

	tcapBytes, err := tcap.NewBeginInvokeWithDialogue(
		uint32(*otid),             // OTID
		tcap.DialogueAsID,         // DialogueType
		tcap.InfoRetrievalContext, // ACN
		3,                         // ACN Version
		0,                         // Invoke Id
		*opcode,                   // OpCode
		p,                         // Payload
	).MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	// create *Config to be used in M3UA connection
	m3config := m3ua.NewConfig(
		parsePC(opc),            // OriginatingPointCode
		parsePC(dpc),            // DestinationPointCode
		m3params.ServiceIndSCCP, // ServiceIndicator
		0,                       // NetworkIndicator
		0,                       // MessagePriority
		1,                       // SignalingLinkSelection
	).EnableHeartbeat(0, 0)

	// setup SCTP peer on the specified IPs and Port.
	remoteAddr, err := sctp.ResolveSCTPAddr("sctp", *raddr)
	if err != nil {
		log.Fatalf("Failed to resolve remote SCTP address: %s", err)
	}

	localAddr, err := sctp.ResolveSCTPAddr("sctp", *laddr)
	if err != nil {
		log.Fatalf("Failed to resolve local SCTP address: %s", err)
	}

	// setup underlying SCTP/M3UA connection first
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m3conn, err := m3ua.Dial(ctx, "m3ua", localAddr, remoteAddr, m3config)
	if err != nil {
		log.Fatal(err)
	}

	cdPA, err := utils.StrToSwappedBytes(*cdparty, "0")
	if err != nil {
		log.Fatal(err)
	}
	esOfCdPA, esOfCgPA := 0x01, 0x01
	if len(*cdparty)%2 == 0 {
		esOfCdPA = 0x02
	}
	if len(*cgparty)%2 == 0 {
		esOfCgPA = 0x02
	}

	cgPA, err := utils.StrToSwappedBytes(*cgparty, "0")
	if err != nil {
		log.Fatal(err)
	}

	// create UDT message with CdPA, CgPA and payload
	udt, err := sccp.NewUDT(
		1,    // Protocol Class
		true, // Message handling
		params.NewPartyAddress( // CalledPartyAddress: 1234567890123456
			0x12, 0, 6, 0x00, // Indicator, SPC, SSN, TT
			0x01, esOfCdPA, 0x04, // NP, ES, NAI
			cdPA, // GlobalTitleInformation
		),
		params.NewPartyAddress( // CallingPartyAddress: 9876543210
			0x12, 0, 7, 0x00, // Indicator, SPC, SSN, TT
			0x01, esOfCgPA, 0x04, // NP, ES, NAI
			cgPA, // GlobalTitleInformation
		),
		tcapBytes,
	).MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	// send once
	streamId := 1
	if _, err := m3conn.Write(udt, streamId); err != nil {
		log.Fatal(err)
	}

	recvBuff := make([]byte, 1500)
	for {
		n, err := m3conn.Read(recvBuff)
		if err != nil {
			// this indicates the conn is no longer alive. close M3UA conn and wait for INIT again.
			if err == io.EOF {
				log.Printf("Closed M3UA conn with: %s, waiting to come back...", m3conn.RemoteAddr())
			}
			// this indicates some unexpected error occurred on M3UA conn.
			log.Printf("Error reading from M3UA conn: %s", err)
		}

		log.Printf("Read: %x\n", recvBuff[:n])
		var sccpMsg sccp.Message
		sccpMsg, err = sccp.ParseMessage(recvBuff)
		if err != nil {
			log.Printf("fail to parse SCCP message: %s", err)
			return
		}
		log.Printf("SCCP Message: %s\n", sccpMsg)

		if sccpMsg.MessageType() == sccp.MsgTypeUDT {
			udtMsg, ok := sccpMsg.(*sccp.UDT)
			if ok == true {
				log.Printf("UDT : %s", udtMsg)

				tcapMsg, te := tcap.ParseBER(udtMsg.Data)
				if te != nil {
					log.Printf("TCAP parse error")
					return
				}
				log.Printf("TCAP Message: %s\n", tcapMsg)

			}
		}

	}
}
