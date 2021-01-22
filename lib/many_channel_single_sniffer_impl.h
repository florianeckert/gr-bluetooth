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

#ifndef INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_IMPL_H
#define INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_IMPL_H

#include <gr_bluetooth/many_channel_single_sniffer.h>
#include <map>
#include <mutex>
#include "gr_bluetooth/piconet.h"

namespace gr {
  namespace bluetooth {

    class many_channel_single_sniffer_impl : public many_channel_single_sniffer
    {
     private:
      std::map<int, basic_rate_piconet::sptr> d_piconets;
      std::mutex d_piconets_mutex;

     public:
      many_channel_single_sniffer_impl(std::vector<int> channels, int sample_rate);
      ~many_channel_single_sniffer_impl();

      // Where all the action really happens
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_IMPL_H */

