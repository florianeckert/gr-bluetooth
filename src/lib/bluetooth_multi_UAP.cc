/* -*- c++ -*- */
/*
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann                                                                                            
 * Copyright 2007 Dominic Spill                                                                                                                   
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * gr-bluetooth is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * gr-bluetooth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with gr-bluetooth; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

/*
 * config.h is generated by configure.  It contains the results
 * of probing for features, options etc.  It should be the first
 * file included in your .cc file.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bluetooth_multi_UAP.h"
#include "bluetooth_packet.h"

/*
 * Create a new instance of bluetooth_multi_UAP and return
 * a boost shared_ptr.  This is effectively the public constructor.
 */
bluetooth_multi_UAP_sptr
bluetooth_make_multi_UAP(double sample_rate, double center_freq, int squelch_threshold, int LAP)
{
  return bluetooth_multi_UAP_sptr (new bluetooth_multi_UAP(sample_rate, center_freq, squelch_threshold, LAP));
}

//private constructor
bluetooth_multi_UAP::bluetooth_multi_UAP(double sample_rate, double center_freq, int squelch_threshold, int LAP)
  : bluetooth_multi_block(sample_rate, center_freq, squelch_threshold)
{
	d_LAP = LAP;
	d_previous_slot = 0;
	set_symbol_history(3125);
	d_piconet = bluetooth_make_piconet(d_LAP);
	printf("lowest channel: %d, highest channel %d\n", d_low_channel, d_high_channel);
}

//virtual destructor.
bluetooth_multi_UAP::~bluetooth_multi_UAP ()
{
}

int 
bluetooth_multi_UAP::work(int noutput_items,
			       gr_vector_const_void_star &input_items,
			       gr_vector_void_star &output_items)
{
	int retval, interval, current_slot, channel;
	char symbols[history()]; //poor estimate but safe

	//FIXME maybe limit to one channel for real-time performance
	for (channel = d_low_channel; channel <= d_high_channel; channel++)
	{
		int num_symbols = channel_symbols(channel, input_items, symbols, history());

		if (num_symbols >= 72 )
		{
			//FIXME this will break with squelch, but we don't want to look beyond one slot for ACs:
			int latest_ac = (num_symbols - 72) < 625 ? (num_symbols - 72) : 625;
			retval = bluetooth_packet::sniff_ac(symbols, latest_ac);
			if(retval > -1) {
				bluetooth_packet_sptr packet = bluetooth_make_packet(&symbols[retval], num_symbols - retval);
				if(packet->get_LAP() == d_LAP) {
					current_slot = (int) (d_cumulative_count / d_samples_per_slot);
					interval = current_slot - d_previous_slot;
					if (d_piconet->UAP_from_header(packet, interval, channel))
						exit(0);
					d_previous_slot = current_slot;
					break;
				}
			}
		}
	}
	d_cumulative_count += (int) d_samples_per_slot;

    /* 
	 * The runtime system wants to know how many output items we produced, assuming that this is equal
	 * to the number of input items consumed.  We tell it that we produced/consumed one time slot of
	 * input items so that our next run starts one slot later.
	 */
	return (int) d_samples_per_slot;
}