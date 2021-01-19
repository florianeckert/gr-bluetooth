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

#ifndef INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_H
#define INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_H

#include <bluetooth/api.h>
#include <gnuradio/hier_block2.h>

namespace gr {
  namespace bluetooth {

    /*!
     * \brief <+description of block+>
     * \ingroup bluetooth
     *
     */
    class GR_BLUETOOTH_API many_channel_single_sniffer : virtual public gr::hier_block2
    {
     public:
      typedef boost::shared_ptr<many_channel_single_sniffer> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of bluetooth::many_channel_single_sniffer.
       *
       * To avoid accidental use of raw pointers, bluetooth::many_channel_single_sniffer's
       * constructor is in a private implementation
       * class. bluetooth::many_channel_single_sniffer::make is the public interface for
       * creating new instances.
       */
      static sptr make(std::vector<int> channels, int sample_rate);
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_MANY_CHANNEL_SINGLE_SNIFFER_H */

