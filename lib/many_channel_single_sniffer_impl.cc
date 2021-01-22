/* -*- c++ -*- */
/*
 * Copyright 2021 gr-bluetooth author.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
#include "many_channel_single_sniffer_impl.h"
#include "gr_bluetooth/single_sniffer.h"

namespace gr {
  namespace bluetooth {

    many_channel_single_sniffer::sptr
    many_channel_single_sniffer::make(std::vector<int> channels, int sample_rate)
    {
      return gnuradio::get_initial_sptr
        (new many_channel_single_sniffer_impl(channels, sample_rate));
    }


    /*
     * The private constructor
     */
    many_channel_single_sniffer_impl::many_channel_single_sniffer_impl(std::vector<int> channels, int sample_rate)
      : gr::hier_block2("many_channel_single_sniffer",
              gr::io_signature::make(channels.size(), channels.size(), sizeof(gr_complex)),
              gr::io_signature::make(0, 0, 0))
    {
      single_sniffer::map_ptr pn_pointer = std::make_shared<std::map<int, basic_rate_piconet::sptr>>(d_piconets);
      for(int i=0; i<channels.size(); i++) {
        int channel = channels[i];
        int channel_freq = 2402000000 + channel*1000000;
        single_sniffer::sptr sniffer = single_sniffer::make(sample_rate, channel_freq, pn_pointer, d_piconets_mutex);
        connect(self(), i, sniffer, 0);
      }
    }

    /*
     * Our virtual destructor.
     */
    many_channel_single_sniffer_impl::~many_channel_single_sniffer_impl()
    {
    }


  } /* namespace bluetooth */
} /* namespace gr */

