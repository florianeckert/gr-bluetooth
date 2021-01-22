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

    no_filter_sniffer::sptr no_filter_sniffer::make(double sample_rate, double center_freq, map_ptr piconets, std::mutex &piconets_mutex)
    {
        return gnuradio::get_initial_sptr (new no_filter_sniffer_impl(sample_rate, center_freq, piconets, piconets_mutex));
    }

    /*
     * The private constructor
     */
    no_filter_sniffer_impl::no_filter_sniffer_impl(double sample_rate, double center_freq, map_ptr piconets, std::mutex &piconets_mutex)
        : gr::sync_block ("bluetooth no filter sniffer block",
                gr::io_signature::make (1, 1, sizeof (int8_t)),
                gr::io_signature::make (0, 0, 0)),
            d_tag_key(pmt::string_to_symbol("timestamp")),
            d_basic_rate_piconets(piconets),
            d_piconets_mutex(piconets_mutex)
    {
        /* set channel_freq and channel to bluetooth channel closest to center freq */
        double center = (center_freq - BASE_FREQUENCY) / CHANNEL_WIDTH;
        d_channel = round(center);
        d_channel_freq = BASE_FREQUENCY + (d_channel * CHANNEL_WIDTH);

        ///* we want to have 5 slots (max packet length) available in the history */
        //set_history((sample_rate/SYMBOL_RATE)*SYMBOLS_FOR_BASIC_RATE_HISTORY);

        // keep length of one access code in history to detect new frames
        //set_history((sample_rate/SYMBOL_RATE)*SYMBOLS_PER_BASIC_RATE_ACCESS_CODE);

        d_last_time_tag = tag_t();
        // mark to be unset
        d_last_time_tag.offset=UINT64_MAX;
    }

    /*
     * Our virtual destructor.
     */
    no_filter_sniffer_impl::~no_filter_sniffer_impl()
    {
    }

    int no_filter_sniffer_impl::work( int noutput_items,
            gr_vector_const_void_star& input_items,
            gr_vector_void_star&       output_items )
    {
        if (d_last_time_tag.offset==UINT64_MAX) {
            std::vector<tag_t> v;
            get_tags_in_window(v, 0, 0, 1, d_tag_key);
            if (v.size()==0) {
                std::cerr << "failed to find time tag at start of stream" << std::endl;
                // unset mark to prevent errors
                d_last_time_tag.offset=0;
            }
            else {
                d_last_time_tag = v[0];
            }
        }
        std::vector<tag_t> tmp_v;
        get_tags_in_window(tmp_v, 0, 0, noutput_items, d_tag_key);
        for(std::vector<int>::size_type i = 0; i != tmp_v.size(); i++) {
            float tmp_tag_time = pmt::to_float(tmp_v[i].value)/1000000;
            //std::cout << "at " << tmp_v[i].offset << " - " << pmt::symbol_to_string(tmp_v[i].key) << ": " << tmp_tag_time << std::endl;
        }
      

        char* in = (char*) input_items[0];
        // search within the whole input buffer, i.e. number of inputs plus history
        // (minus 1 as history includes first unconsumed input item) 
        int search_length = history()-1+noutput_items;
        // find index to start of packet via access code
        int offset = classic_packet::sniff_ac(in, search_length);
        int items_consumed = 0;
        
        // ac found -> handle it
        if (offset>=0) {
            // calculate time of frame from tags
            // look for most current tag
            std::vector<tag_t> vec;
            get_tags_in_window(vec, 0, 0, offset+1, d_tag_key);
            tag_t tag;
            if (vec.size()==0) {
                tag = d_last_time_tag;
            }
            else {
                tag = vec.back();
            }
            // calculate sample index from last tag
            // received time from tag is expected to be µs
            // 1 sample == 1µs, as this blocks sample rate is fixed at 1MHz
            int tag_sample_index = (int) pmt::to_float(tag.value);
            // absolute index of detected offset
            int abs_off = nitems_read(0)+offset;
            // sample index distance between last tag and detected offset
            int tag_distance = abs_off - tag.offset;
            std::cout << "tag distance: " << tag_distance << std::endl;
            
            // handle ac at detected index/offset. max_len is remaining items in buffer
            ac(&in[offset], search_length-offset, d_channel_freq, tag_sample_index+tag_distance);
            std::cout << "#samples: " << (int) tag_sample_index+tag_distance << std::endl;
            std::cout << "time: " << (tag_sample_index+tag_distance)/1000000 << std::endl;
            // we consume only one shortened access code (and all items before) as we want
            // to look for potential new access codes after this
            items_consumed = offset + SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE;
            // make sure we dont consume too much
            // this should not be possible in theory, as then no access code would have been
            // detected
            items_consumed = (items_consumed > noutput_items) ? noutput_items : items_consumed;
        }
        // no AC was found in the whole buffer
        else {
            // we can consume all new items
            items_consumed = noutput_items;
        }
        // save last tag in case next time a frame is detected w/o a tag for items in the buffer
        std::vector<tag_t> v;
        get_tags_in_window(v, 0, 0, noutput_items, d_tag_key);
        if (v.size() != 0) {
            d_last_time_tag = v.back();
        } 
        
        return (int) items_consumed;
    }

    /* handle AC
     * symbols - pointer to the symbols containing access code and potential frame
     * max_len - maximum number of items that can be consumed
     * freq    - frequency of the channel
     * offset  - position in terms of relative items
     */
//    void no_filter_sniffer_impl::ac(char *symbols, int max_len, double freq, int offset)
//    {
//        /* native (local) clock in 625 us */	
//        uint32_t clkn = (int) ((d_cumulative_count+offset-history()) / 625) & 0x7ffffff;
//        /* same clock in ms */
//        double time_ms = ((double) d_cumulative_count+offset-history())/1000;
    void no_filter_sniffer_impl::ac(char *symbols, int max_len, double freq, int abs_index)
    {
        /* native (local) clock in 625 us */	
        uint32_t clkn = (int) ((abs_index) / 625) & 0x7ffffff;
        /* same clock in ms */
        double time_ms = ((double) abs_index)/1000;
        classic_packet::sptr pkt = classic_packet::make(symbols, max_len, clkn, freq);
        uint32_t lap = pkt->get_LAP();

        printf("time %6d (%6.1f ms), channel %2d, LAP %06x ", 
                clkn, time_ms, pkt->get_channel( ), lap);

        if (pkt->header_present()) {
            if (!get_piconet(lap)) {
                set_piconet(lap, basic_rate_piconet::make(lap));
            }
            basic_rate_piconet::sptr pn = get_piconet(lap);

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
                set_piconet(lap, NULL);
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
        if (!get_piconet(lap)) {
            set_piconet(lap, basic_rate_piconet::make(lap));
        }
        pn = get_piconet(lap);

        pn->set_UAP(uap);
        pn->set_NAP(nap);
        pn->set_offset(offset);
        //FIXME if this is a role switch, the offset can have an error of as
        //much as 1.25 ms 
    }

    void no_filter_sniffer_impl::set_piconet(int lap, basic_rate_piconet::sptr pn) {
        std::lock_guard<std::mutex> guard(d_piconets_mutex);
        std::map<int, basic_rate_piconet::sptr> &piconets_map = *d_basic_rate_piconets;
        if (!pn) {
            piconets_map.erase(lap);
            std::cout << "erased " << lap << std::endl;
        }
        else {
            piconets_map[lap] = pn;
        }
    }

    basic_rate_piconet::sptr no_filter_sniffer_impl::get_piconet(int lap) {
        std::lock_guard<std::mutex> guard(d_piconets_mutex);
        std::map<int, basic_rate_piconet::sptr> &piconets_map = *d_basic_rate_piconets;
        return piconets_map[lap];
    }

} /* namespace bluetooth */
} /* namespace gr */

