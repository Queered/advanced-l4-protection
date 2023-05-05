package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pfring"
    "log"
    "time"
    "os/exec"
    "net"
)

func main() {
  
    handle, err := pfring.Open("eth0")
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

  g
    handle.SetDirection(pcap.DirectionIn)


    handle.SetBPFFilter("tcp or udp or (udp port 123) or (udp port 2000) or (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) or (udp port 5555 or udp port 2323)")


    handle.SetPollWatermark(50)


    handle.SetTimeout(time.Second)


    ipPackets := make(map[string]int)


    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // get the ip layer from the packet
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        if ipLayer == nil {
            continue
        }

  
        srcIP := ipLayer.(*layers.IPv4).SrcIP

      
        ipPackets[srcIP.String()]++


        if ipPackets[srcIP.String()] > 100 {
            // block the ip via tables yk
            cmd := exec.Command("iptables", "-A", "INPUT", "-s", srcIP.String(), "-j", "DROP")
            err = cmd.Run()
            if err != nil {
                fmt.Println(err)
            } else {
                fmt.Println("Blocked IP: ", srcIP.String())
            }
            // remove the IP from the map
            delete(ipPackets, srcIP.String())
        }
    }
}
