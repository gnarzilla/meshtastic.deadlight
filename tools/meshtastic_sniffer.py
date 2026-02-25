#!/usr/bin/env python3
import sys
import signal
import time
from gnuradio import blocks
from gnuradio import gr
import osmosdr
import lora

class meshtastic_sniffer(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "Meshtastic Sniffer")

        # --- Configuration for US (Long Fast) ---
        self.freq = 915.0e6      # Center Frequency
        self.sf = 11             # Spreading Factor (Long Fast default)
        self.bw = 250000         # Bandwidth (250k)
        self.samp_rate = 1e6     # 1 MSPS (Must be > bw)
        
        print(f"[*] Configuring RTL-SDR...")
        print(f"    Freq: {self.freq/1e6} MHz")
        print(f"    SF: {self.sf} | BW: {self.bw}")

        # --- 1. RTL-SDR Source ---
        self.osmosdr_source = osmosdr.source(args="numchan=1")
        self.osmosdr_source.set_sample_rate(self.samp_rate)
        self.osmosdr_source.set_center_freq(self.freq, 0)
        self.osmosdr_source.set_freq_corr(0, 0)
        self.osmosdr_source.set_dc_offset_mode(0, 0)
        self.osmosdr_source.set_iq_balance_mode(0, 0)
        self.osmosdr_source.set_gain_mode(False, 0)
        self.osmosdr_source.set_gain(40, 0) # Gain: 40dB (Adjust if deaf)
        self.osmosdr_source.set_if_gain(20, 0)
        self.osmosdr_source.set_bb_gain(20, 0)
        self.osmosdr_source.set_antenna('', 0)
        self.osmosdr_source.set_bandwidth(0, 0)

        # --- 2. LoRa Receiver ---
        # The magic block from rpp0/gr-lora
        # Args: (samp_rate, center_freq, [channel_list], bw, sf, implicit_header, cr, crc, low_dr, loop, decimation, capture)
        self.lora_receiver = lora.lora_receiver(
            self.samp_rate, 
            self.freq, 
            [self.freq], 
            self.bw, 
            self.sf, 
            False, # Implicit header
            4,     # Coding Rate (4/4)
            True,  # CRC Enabled
            False, # Low Data Rate Optimization
            False, # Loop
            1,     # Decimation
            False, # Capture
            False  # Verbose
        )

        # --- 3. Message Output ---
        self.message_debug = blocks.message_debug()

        # --- Connections ---
        # Raw IQ from SDR -> LoRa Decoder
        self.connect((self.osmosdr_source, 0), (self.lora_receiver, 0))
        # Decoded frames -> Print to Screen
        self.msg_connect((self.lora_receiver, 'frames'), (self.message_debug, 'print'))

def main():
    tb = meshtastic_sniffer()
    
    # Handle Ctrl+C
    def sig_handler(sig=None, frame=None):
        print("\nStopping sniffer...")
        tb.stop()
        tb.wait()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    print("[*] Sniffer running. Send a message on your mesh now!")
    print("[*] Press Ctrl+C to stop.")
    
    # Keep the script alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
