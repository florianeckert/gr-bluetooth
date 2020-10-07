/* -*- c++ -*- */
/* 
 * Copyright 2013 Christopher D. Kilgour
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann
 * Copyright 2007 Dominic Spill
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "no_filter_sniffer_impl.h"

namespace gr {
namespace bluetooth {

    no_filter_sniffer::sptr no_filter_sniffer::make(double sample_rate, double center_freq,
                double squelch_threshold, bool tun)
        {
            return gnuradio::get_initial_sptr (new no_filter_sniffer_impl(sample_rate, center_freq, 
                        squelch_threshold, tun));
        }

    /*
     * The private constructor
     */
    no_filter_sniffer_impl::no_filter_sniffer_impl(double sample_rate, double center_freq,
            double squelch_threshold, bool tun)
        : multi_block(sample_rate, center_freq, squelch_threshold),
        gr::sync_block ("bluetooth multi sniffer block",
                gr::io_signature::make (1, 1, sizeof (gr_complex)),
                gr::io_signature::make (0, 0, 0))
    {
        d_tun = tun;
        set_symbol_history(SYMBOLS_FOR_BASIC_RATE_HISTORY);

        /* Tun interface */
        if (d_tun) {
            strncpy(d_chan_name, "btbb", sizeof(d_chan_name)-1);
            if ((d_tunfd = mktun(d_chan_name, d_ether_addr)) == -1) {
                fprintf(stderr,
                        "warning: was not able to open TUN device, "
                        "disabling Wireshark interface\n");
                // throw std::runtime_error("cannot open TUN device");
            }
        }
    }

    /*
     * Our virtual destructor.
     */
    no_filter_sniffer_impl::~no_filter_sniffer_impl()
    {
    }

    int no_filter_sniffer_impl::work( int                        noutput_items,
                gr_vector_const_void_star& input_items,
                gr_vector_void_star&       output_items )
        {
            for (double freq = d_low_freq; freq <= d_high_freq; freq += 1e6) {   
                gr_complex *ch_samples = new gr_complex[noutput_items+100000];
                gr_vector_void_star btch( 1 );
                btch[0] = ch_samples;
                double on_channel_energy, snr;
                int ch_count = channel_samples( freq, input_items, btch, on_channel_energy, history() );

                /* number of symbols available */
                int sym_length = history();
                char *symbols = new char[sym_length];
                /* pointer to our starting place for sniff_ */
                char *symp = symbols;
                gr_vector_const_void_star cbtch( 1 );
                cbtch[0] = ch_samples;
                int len = channel_symbols( cbtch, symbols, ch_count );
                delete [] ch_samples;

                int limit = ((len - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) < SYMBOLS_PER_BASIC_RATE_SLOT) ? 
                    (len - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) : SYMBOLS_PER_BASIC_RATE_SLOT;

                /* look for multiple packets in this slot */
                while (limit >= 0) {
                    /* index to start of packet */
                    int i = classic_packet::sniff_ac(symp, limit);
                    if (i >= 0) {
                        int step = i + SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE;
                        ac(&symp[i], len - i, freq, snr);
                        len   -= step;
                        if(step >= sym_length)
                        {
                            fprintf(stderr, "Error: %s\n", "Bad step"); 
                            abort();
                        }
                        symp   = &symp[step];
                        limit -= step;
                    } 
                    else {
                        break;
                    }
                }
                delete [] symbols;
            }
            d_cumulative_count += (int) d_samples_per_slot;

            /* 
             * The runtime system wants to know how many output items we
             * produced, assuming that this is equal to the number of input
             * items consumed.  We tell it that we produced/consumed one
             * time slot of input items so that our next run starts one slot
             * later.
             */
            return (int) d_samples_per_slot;
        }

    /* handle AC */
    void no_filter_sniffer_impl::ac(char *symbols, int len, double freq, double snr)
        {
            /* native (local) clock in 625 us */	
            uint32_t clkn = (int) (d_cumulative_count / d_samples_per_slot) & 0x7ffffff;
            classic_packet::sptr pkt = classic_packet::make(symbols, len, clkn, freq);
            uint32_t lap = pkt->get_LAP();

            printf("time %6d, snr=%.1f, channel %2d, LAP %06x ", 
                    clkn, snr, pkt->get_channel( ), lap);

            if (pkt->header_present()) {
                if (!d_basic_rate_piconets[lap]) {
                    d_basic_rate_piconets[lap] = basic_rate_piconet::make(lap);
                }
                basic_rate_piconet::sptr pn = d_basic_rate_piconets[lap];

                if (pn->have_clk6() && pn->have_UAP()) {
                    decode(pkt, pn, true);
                } 
                else {
                    discover(pkt, pn);
                }

                /*
                 * If this is an inquiry response, saving the piconet state will only
                 * cause problems later.
                 */
                if (lap == GIAC || lap == LIAC) {
                    d_basic_rate_piconets.erase(lap);
                }
            } 
            else {
                id(lap);
            }
        }

    /* handle ID packet (no header) */
    void no_filter_sniffer_impl::id(uint32_t lap)
    {
        printf("ID\n");
        if (d_tun) {
            write_interface(d_tunfd, NULL, 0, 0, lap, ETHER_TYPE);
        }
    }

    /* decode packets with headers */
    void no_filter_sniffer_impl::decode(classic_packet::sptr pkt,
            basic_rate_piconet::sptr pn, 
            bool first_run)
    {
        uint32_t clock; /* CLK of target piconet */

        clock = (pkt->d_clkn + pn->get_offset());
        pkt->set_clock(clock, pn->have_clk27());
        pkt->set_UAP(pn->get_UAP());

        pkt->decode();

        if (pkt->got_payload()) {
            pkt->print();
            if (d_tun) {
                uint64_t addr = (pkt->get_UAP() << 24) | pkt->get_LAP();

                if (pn->have_NAP()) {
                    addr |= ((uint64_t) pn->get_NAP()) << 32;
                    pkt->set_NAP(pn->get_NAP());
                }

                /* include 9 bytes for meta data & packet header */
                int length = pkt->get_payload_length() + 9;
                char *data = pkt->tun_format();

                write_interface(d_tunfd, (unsigned char *)data, length,
                        0, addr, ETHER_TYPE);
                free(data);
            }
            if (pkt->get_type() == 2)
                fhs(pkt);
        } else if (first_run) {
            printf("lost clock!\n");
            pn->reset();

            /* start rediscovery with this packet */
            discover(pkt, pn);
        } else {
            printf("Giving up on queued packet!\n");
        }
    }

    /* work on UAP/CLK1-6 discovery */
    void no_filter_sniffer_impl::discover(classic_packet::sptr pkt,
            basic_rate_piconet::sptr pn)
    {
        printf("working on UAP/CLK1-6\n");

        /* store packet for decoding after discovery is complete */
        pn->enqueue(pkt);

        if (pn->UAP_from_header(pkt))
            /* success! decode the stored packets */
            recall(pn);
    }

    /* decode stored packets */
    void no_filter_sniffer_impl::recall(basic_rate_piconet::sptr pn)
    {
        packet::sptr pkt;
        printf("Decoding queued packets\n");

        while (pkt = pn->dequeue()) {
            classic_packet::sptr cpkt = boost::dynamic_pointer_cast<classic_packet>(pkt);
            printf("time %6d, channel %2d, LAP %06x ", cpkt->d_clkn,
                    cpkt->get_channel(), cpkt->get_LAP());
            decode(cpkt, pn, false);
        }

        printf("Finished decoding queued packets\n");
    }

    /* pull information out of FHS packet */
    void no_filter_sniffer_impl::fhs(classic_packet::sptr pkt)
    {
        uint32_t lap;
        uint8_t uap;
        uint16_t nap;
        uint32_t clk;
        uint32_t offset;
        basic_rate_piconet::sptr pn;

        /* caller should have checked got_payload() and get_type() */

        lap = pkt->lap_from_fhs();
        uap = pkt->uap_from_fhs();
        nap = pkt->nap_from_fhs();

        /* clk is shifted to put it into units of 625 microseconds */
        clk = pkt->clock_from_fhs() << 1;
        offset = (clk - pkt->d_clkn) & 0x7ffffff;

        printf("FHS contents: BD_ADDR ");

        printf("%2.2x:", (nap >> 8) & 0xff);
        printf("%2.2x:", nap & 0xff);
        printf("%2.2x:", uap);
        printf("%2.2x:", (lap >> 16) & 0xff);
        printf("%2.2x:", (lap >> 8) & 0xff);
        printf("%2.2x", lap & 0xff);

        printf(", CLK %07x\n", clk);

        /* make use of this information from now on */
        if (!d_basic_rate_piconets[lap]) {
            d_basic_rate_piconets[lap] = basic_rate_piconet::make(lap);
        }
        pn = d_basic_rate_piconets[lap];

        pn->set_UAP(uap);
        pn->set_NAP(nap);
        pn->set_offset(offset);
        //FIXME if this is a role switch, the offset can have an error of as
        //much as 1.25 ms 
    }

} /* namespace bluetooth */
} /* namespace gr */

